
rule Trojan_BAT_Kilim_D{
	meta:
		description = "Trojan:BAT/Kilim.D,SIGNATURE_TYPE_PEHSTR,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f 63 73 70 2e 70 68 70 } //2 facebook.com/csp.php
		$a_01_1 = {63 68 72 6f 6d 65 2e 74 61 62 73 2e 72 65 6d 6f 76 65 28 90 02 10 2e 69 64 29 3b } //2
		$a_01_2 = {78 68 72 2e 72 65 73 70 6f 6e 73 65 54 65 78 74 } //1 xhr.responseText
		$a_01_3 = {78 68 72 2e 6f 70 65 6e 28 22 47 45 54 22 } //1 xhr.open("GET"
		$a_01_4 = {78 68 72 2e 73 65 6e 64 28 29 3b } //1 xhr.send();
		$a_01_5 = {4d 61 74 68 2e 72 61 6e 64 6f 6d 28 29 } //1 Math.random()
		$a_01_6 = {22 62 6c 6f 63 6b 69 6e 67 22 } //1 "blocking"
		$a_01_7 = {75 72 6c 2e 69 6e 64 65 78 4f 66 28 27 64 65 76 74 6f 6f 6c 73 3a 2f 2f 27 29 } //1 url.indexOf('devtools://')
		$a_01_8 = {63 68 72 6f 6d 65 3a 2f 2f 65 78 74 65 6e 73 69 6f 6e 73 2f } //1 chrome://extensions/
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}