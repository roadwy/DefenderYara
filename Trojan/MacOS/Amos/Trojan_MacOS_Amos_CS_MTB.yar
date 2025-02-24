
rule Trojan_MacOS_Amos_CS_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CS!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {48 ff c3 4c 89 ff 4c 89 f6 48 89 da 5b 41 5c 41 5e 41 5f 5d e9 82 00 00 00 } //1
		$a_00_1 = {55 48 89 e5 48 89 f8 48 8b 3f 48 85 ff 74 09 48 89 78 08 e8 32 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}