
$( document ).ready(function() {

	$.support.cors=true;
	//$.mobile.allowCrossDomainPages = true;

	$('#http-request-button').click(function() {

		var url = $('#http-request-url-id').val();
		var port = $('#http-request-port-id').val();

		if(!port) {port=80;}
		if(!url) {url='www.github.com';}

		$('.server-class').html('<b>Server:</b> ' + url + ':' + port);

        $('#socket-response-id').html('<b>Response:</b><span style="color:red"> please wait while loading</span>');

		var socketStarttime = new Date().getTime(); // for duration
		var dt = new Date(); // for pretty timestamp
		var time = dt.getHours() + ":" + dt.getMinutes() + ":" + dt.getSeconds();
		$('#socket-start-time-id').html('<b>Start:</b> ' + time);

		var socket = new Socket();
		socket.open(
		  url,
		  port,
		  function() {
			$('#socket-response-id').html('<b>Response:</b> none (success)' );
			var endTime = new Date().getTime();
			var totalTime = endTime - socketStarttime;
			$('#socket-duration-time-id').html('<b>Duration:</b> ' + totalTime/1000 + ' seconds');
		  },
		  function(errorMessage) {
			$('#socket-response-id').html('<b>Response:</b> ' + errorMessage);
			var endTime = new Date().getTime();
			var totalTime = endTime - socketStarttime;
			$('#socket-duration-time-id').html('<b>Duration:</b> ' + totalTime/1000 + ' seconds');
		});

		// HTTZ Request
		$('#http-response-id').html('<b>HTTZ Response:</b><span style="color:red"> please wait while loading</span>');
		var httpStarttime = new Date().getTime(); // for duration
		var dt = new Date(); // for pretty timestamp
		var time = dt.getHours() + ":" + dt.getMinutes() + ":" + dt.getSeconds();
		$('#http-start-time-id').html('<b>Start:</b> ' + time);

		$.ajax({
		    url: 'http://'+url,
		    type: 'get',
		    crossDomain: true,
		    datatype: 'application/json',
		    success: function (data, textStatus, request) {
		      $('#http-response-id').html('<b>Code:</b>: ' + request.getResponseHeader('status') + ' ' + textStatus);   
		    },
		    error: function(data, textStatus, e) {
				$('#http-response-id').html('<b>Status:</b> ' + e.status + '<br><b>HTTP Text:</b> ' + e.statusText);   
			}  
		}).done(function() {
			var endTime = new Date().getTime();
			var totalTime = endTime - httpStarttime;
			$('#http-duration-time-id').html('<b>Duration:</b> ' + totalTime/1000 + ' seconds');
		});

	});

});