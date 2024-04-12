const term = new Terminal({rows: 40});
term.open(document.getElementById('terminal'));

var Module = {
	onRuntimeInitialized: function() {
	},

	print: function(str) {
		term.writeln(str)
	}
}

function get_bytes()
{
	var inVals = Array();
	var inTxt = document.getElementById("myinput").value;
	inTxt = inTxt.replace(/^radix:(.*)$/gmi, "");
	inTxt = inTxt.replace(/(\/\*(.*?)\*\/)|(\/\/(.*?)$)|[g-w]|[yz]/gmi, ""); // strip C/C++ comments, non-hex chars
	document.getElementById("myinput").value = inTxt;
	var inSplit = inTxt.split(/(?![+-])\W/); // split by all non-alphanumeric characters
	if(inSplit.length === 1 && inSplit[0].length > 2) {
		// split every 2 chars
		inSplit = inSplit[0].match(/.{1,2}/g);
	}

	// split every 2 chars
	inSplit.forEach((e) => {
		var x = parseInt(e, 16);
		if (x >= 0 && x <= 0xFF) {
			inVals.push(x);
		}
	})

	return inVals;
}

function parse_4wire()
{
	// document.getElementById("myoutput").value = "";

	// Create example data to test float_multiply_array
	var data = get_bytes();

	// Get data byte size, allocate memory on Emscripten heap, and get pointer
	var buffer = Module._malloc(data.length);

	Module.HEAPU8.set(data, buffer)
	// Call function and get result
	_hci_4wire_parse(buffer, data.length, true);

	// Free memory
	Module._del(buffer);
}

function parse_3wire()
{
	// document.getElementById("myoutput").value = "";

	// Create example data to test float_multiply_array
	var data = get_bytes();

	// Get data byte size, allocate memory on Emscripten heap, and get pointer
	var buffer = Module._malloc(data.length);

	Module.HEAPU8.set(data, buffer)
	// Call function and get result
	_hci_3wire_parse(buffer, data.length, true);

	// Free memory
	Module._del(buffer);
}

// convert the form to JSON
const getFormJSON = (form) => {
  const data = new FormData(form);
  return Array.from(data.keys()).reduce((result, key) => {
    if (result[key]) {
      result[key] = data.getAll(key)
      return result
    }
    result[key] = data.get(key);
    return result;
  }, {});
};

// handle the form submission event, prevent default form behaviour, check validity, convert form to JSON
const capture = async (event) => {
  const element = event.target;
  event.preventDefault();
  if (!element.reportValidity()) {
  	return;
	}
  const option = getFormJSON(element);
  const parser = _hci_parse_new(true, option.transport === "H4");
  const port = await navigator.serial.requestPort();
	await port.open(option).then(async () => {
		const reader = port.readable.getReader();
		// while (port.readable) {
			try {
				while (true) {
					const {value, done} = await reader.read();
					if (done) {
						reader.releaseLock();
						break;
					}
					// console.log(value);
					var buffer = Module._malloc(value.length);
					Module.HEAPU8.set(value, buffer);
					_hci_parse_process(parser, buffer, value.length);
					Module._del(buffer);
				}
			} catch(e) {
				
			} finally {
			// 	reader.releaseLock();
			}
		// }
		await port.close();
	})
}

document.querySelector('form#monitor').addEventListener("submit", capture)
document.querySelector('form#monitor input#stop').addEventListener("click", async (event) => {
	
})
