
rule Trojan_BAT_Zusy_SL_MTB{
	meta:
		description = "Trojan:BAT/Zusy.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 8f 19 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd } //2
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 server.Resources.resources
		$a_01_2 = {47 61 74 70 68 6f 72 20 50 69 6e 65 69 63 65 20 41 6c 6c 20 52 69 67 68 74 20 52 65 73 65 72 76 65 64 } //2 Gatphor Pineice All Right Reserved
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}