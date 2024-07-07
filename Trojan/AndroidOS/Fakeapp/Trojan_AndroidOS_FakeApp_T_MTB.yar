
rule Trojan_AndroidOS_FakeApp_T_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6c 6f 6f 6b 70 69 6e 6b 2e 78 79 7a 2f 6c 61 6e 64 69 6e 67 2e 70 68 70 2f 3f 61 70 70 } //1 lookpink.xyz/landing.php/?app
		$a_00_1 = {41 75 74 6f 52 65 73 70 6f 6e 64 65 72 } //1 AutoResponder
		$a_00_2 = {69 6e 73 69 64 65 20 73 65 6e 64 52 65 70 6c 79 } //1 inside sendReply
		$a_00_3 = {41 70 70 6c 79 20 4e 65 77 20 50 69 6e 6b 2a 20 4c 6f 6f 6b 20 6f 6e 20 59 6f 75 72 20 57 68 61 74 73 61 70 70 20 41 6e 64 20 45 6e 6a 6f 79 20 57 68 61 74 73 20 61 70 70 20 6e 65 77 20 46 65 61 74 75 72 65 73 } //1 Apply New Pink* Look on Your Whatsapp And Enjoy Whats app new Features
		$a_00_4 = {2e 78 79 7a 2f 3f 77 68 61 74 73 61 70 70 } //1 .xyz/?whatsapp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}