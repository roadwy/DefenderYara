
rule Trojan_MacOS_Amos_AK_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AK!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 48 89 e5 41 56 53 48 89 fb e8 81 f1 ff ff 48 89 df e8 07 16 00 00 5b 41 5e 5d c3 } //1
		$a_01_1 = {c6 45 d7 00 48 8d 75 d7 48 89 df e8 a8 fc ff ff 48 83 c4 18 5b 41 5c 41 5d 41 5e 41 5f 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}