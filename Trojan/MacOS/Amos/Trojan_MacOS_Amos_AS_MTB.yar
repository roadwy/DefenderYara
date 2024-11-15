
rule Trojan_MacOS_Amos_AS_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AS!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 95 58 ff ff ff 30 11 0f b6 95 58 ff ff ff 30 51 01 30 51 02 0f b6 95 58 ff ff ff 30 51 03 30 51 04 48 83 c1 05 48 39 c1 } //1
		$a_01_1 = {48 8b 4b f8 49 89 4f f8 0f 10 4b e8 41 0f 11 4f e8 49 83 c7 e8 0f 11 43 e8 48 c7 43 f8 00 00 00 00 48 8d 4b e8 48 89 cb 4c 39 f1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}