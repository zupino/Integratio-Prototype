
$( document ).ready(function() {

	$.support.cors=true;
	//$.mobile.allowCrossDomainPages = true;

	$('#http-request-button').click(function() {

		var url = $('#http-request-url-id').val();
		$('#http-request-id').html('<b>Host Request:</b> ' + url);

		$('#socket-response-id').html('<b>Socket Response:</b><span style="color:red"> please wait while loading</span>');

		var socket = new Socket();
		socket.open(
		  url,
		  80,
		  function() {
			$('#socket-response-id').html('<b>Socket Response:</b> none (success)' ); 
		  },
		  function(errorMessage) {
			$('#socket-response-id').html('<b>Socket Response:</b> ' + errorMessage);   
		});

		$.ajax({
		    url: 'http://'+url,
		    type: 'get',
		    crossDomain: true,
		    datatype: 'application/json',
		    success: function (resp) {
		      $('#http-response-id').html('<b>HTTP Response:</b> 200' + '<br><b>HTTP Text:</b> success' );   
		    },
		    error: function(e) {
				$('#http-response-id').html('<b>HTTP Status:</b> ' + e.status + '<br><b>HTTP Text:</b> ' + e.statusText );   
			}  
		});

	});

});