
rule Trojan_BAT_XWorm_BAP_MTB{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 06 08 91 1f 30 59 20 00 01 00 00 58 20 00 01 00 00 5d d1 9d 08 17 58 0c 08 06 8e 69 32 e0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_XWorm_BAP_MTB_2{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 09 06 09 91 05 09 05 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e7 } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}
rule Trojan_BAT_XWorm_BAP_MTB_3{
	meta:
		description = "Trojan:BAT/XWorm.BAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 0a 00 00 0a 13 04 11 04 09 17 73 0b 00 00 0a 13 05 11 05 08 16 08 8e 69 ?? ?? 00 00 0a 11 05 ?? ?? 00 00 0a de 0c 11 05 2c 07 11 05 ?? ?? 00 00 0a dc } //2
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}