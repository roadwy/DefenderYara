
rule Trojan_BAT_Redline_GJK_MTB{
	meta:
		description = "Trojan:BAT/Redline.GJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {04 08 04 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 04 08 17 58 04 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 17 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 04 8e 69 17 59 6a 06 17 58 6e 5a 31 ac 0f 02 04 8e 69 17 59 28 ?? ?? ?? 2b 04 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}