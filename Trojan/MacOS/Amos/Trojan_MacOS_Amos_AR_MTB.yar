
rule Trojan_MacOS_Amos_AR_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AR!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b 56 40 49 8b be 80 00 00 00 49 8b 4e 60 48 01 d1 48 8b 07 4c 89 e6 ?? ?? ?? ?? ?? ?? ?? ff 50 28 89 c3 4c 8b ad 50 ff ff ff 49 8b 7e 40 49 8b 4e 78 49 29 fd 4c 89 fe 4c 89 ea e8 b4 2b 00 00 4c 39 e8 75 ?? 83 fb 01 } //1
		$a_01_1 = {48 09 c8 f3 0f 5e c1 66 0f 3a 0a c0 0a f3 48 0f 2c c8 48 89 ca 48 c1 fa 3f f3 0f 5c 05 8b 3c 00 00 f3 48 0f 2c f0 48 21 d6 48 09 ce 48 39 f0 48 0f 47 f0 4c 89 e7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}