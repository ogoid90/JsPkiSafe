var isValid = false;
var i = 0;

//validaçao do JS
if(getHTML().indexOf("<script") >= 0){
		
	var count = (getHTML().match(/<script/g) || []).length;
		
		while(true){
			
			var form = "formSig".concat(i);
	        var formJs = form.concat(" .js");
		
		    if($('#'+form).length && $('#'+formJs).length){
			
				//content do script
			    var sMsg = $('#'+formJs).html().trim();
				//assinatura
			    var hSig = $('#siggenerated'+i).val();
				//certificado
			    var cert = $('#cert'+i).val();
			
				isValid = doVerify(sMsg, hSig, cert);
				
		    }else{
			
			    if(count > i+1){
					//se existirem scripts sem o form com a assinatura, o js, não é válido
				    isValid = false;
			    }
			
			    break;
		    }
			i = i+1;
	    }
	
}else{
	isValid = true;
}

function getHTML(){
    return document.documentElement.outerHTML
}

function doVerify(sMsg, hSig, cert) {
	
  //carrega o certificado e ve se a assinatura corresponde ao content no script
  var x509 = new X509();
  x509.readCertPEM(cert);
  var isValid = x509.subjectPublicKeyRSA.verifyString(sMsg, hSig);

  return isValid;
}

//depois de validado, se todo o js nao for válido, pergunta se quer continuar, senao volta para a página anterior
if(!isValid){
	if(!confirm("Javascript not signed! Continue anyway?")){
		history.go(-1);
	}
}