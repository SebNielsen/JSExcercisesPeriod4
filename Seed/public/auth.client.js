/**
 * Created by sebastiannielsen on 08/04/2016.
 */
var myApp = angular.module('myApp', ['ngRoute', 'angular-jwt'])

.config(['$routeProvider', function($routeProvider) {
    $routeProvider.when('/home', {
        templateUrl: 'index.html',
        controller: 'Controller'
    });
    $routeProvider.when('/names', {
        templateUrl: 'views/names/names.html',
        controller: 'Controller'
    });
    $routeProvider.when('/hellos', {
        templateUrl: 'views/hellos/hellos.html',
        controller: 'Controller'
    });
}]);

myApp.controller('Controller', function ($scope, $http, $window, $location) {
    $scope.user = {username: '', password: ''};
    $scope.isAuthenticated = false;

    $scope.submit = function () {
        $http
            .post('http://localhost:3000/api/authenticate', $scope.user)
            .success(function (data, status, headers, config) {
                $window.sessionStorage.id_token = data.token;
                $scope.isAuthenticated = true;
                $scope.error = false;
            })
            .error(function (data, status, headers, config) {
                // Erase the token if the user fails to log in
                delete $window.sessionStorage.id_token;
                $scope.isAuthenticated = false;

                // Handle login errors here
                $scope.error = true;
                $scope.msg = 'Error: Invalid user or password';
            });
    };

    $scope.logout = function () {
        $scope.isAuthenticated = false;
        delete $window.sessionStorage.id_token;
        $location.path('/');
    };

    $scope.fetchNames = function () {
        $http({url: 'http://localhost:3000/api/names', method: 'GET'})
            .success(function (data, status, headers, config) {
                $scope.names = data;
            })
            .error(function (data, status, headers, config) {
                $scope.error = true;
                $scope.msg = 'Something went wrong';
            });
    };

    $scope.fetchHellos = function () {
        $http({url: 'http://localhost:3000/api/hellos', method: 'GET'})
            .success(function (data, status, headers, config) {
                $scope.hellos = data;
            })
            .error(function (data, status, headers, config) {
                $scope.error = true;
                $scope.msg = 'Something went wrong';
            });
    };

});


myApp.factory('authInterceptor', function ($rootScope, $q, $window) {

    return {
        request: function (config) {
            config.body = {};
            config.headers = config.headers || {};
            if ($window.sessionStorage.id_token) {
                config.headers.authorization = $window.sessionStorage.id_token;
            }
            return config;
        },
        responseError: function (rejection) {
            if (rejection.status === 401) {
                // handle the case where the user is not authenticated
            }
            return $q.reject(rejection);
        }
    };
});

myApp.config(function ($httpProvider) {
    $httpProvider.interceptors.push('authInterceptor');
});
