var cmInterface = {
	defaultFormat: "MM-DD-YYYY",
	formatDate: function(timestamp, dateFormat) {
		var dateFormat = (dateFormat) ? dateFormat : cmInterface.defaultFormat;
		var time = moment(Number(timestamp));
		var formatted = moment(time).format(dateFormat);
		return formatted;
	}
};


$( document ).ready(function() {
	if (typeof tinymce !== 'undefined') {
  	tinymce.init({ selector:'.profile-edit textarea' });
	}

	if ($('.member-since .date').length) {
		$('.member-since .date').each(function(i) {
			var ts = $(this).text();
			$(this).text(cmInterface.formatDate(ts));
		});
	}
});