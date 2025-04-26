
rule Trojan_BAT_Injuke_SAT_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 32 00 00 0a 25 80 ?? ?? ?? 04 28 02 00 00 2b 28 03 00 00 2b 16 94 28 35 00 00 0a } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //2 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}