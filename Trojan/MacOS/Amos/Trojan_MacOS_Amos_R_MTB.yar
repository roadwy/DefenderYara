
rule Trojan_MacOS_Amos_R_MTB{
	meta:
		description = "Trojan:MacOS/Amos.R!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 63 45 84 48 83 f8 0f 0f 83 25 00 00 00 48 8b 85 58 ff ff ff 48 63 4d 84 8a 54 0d e2 48 63 4d 84 88 54 08 0a 8b 45 84 83 c0 01 89 45 84 } //1
		$a_01_1 = {48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 0f be 04 08 48 8b 8d a0 ee ff ff 8b 09 83 c1 04 31 c8 88 c2 48 8b 85 b0 ee ff ff 48 63 8d 9c ee ff ff 88 14 08 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}