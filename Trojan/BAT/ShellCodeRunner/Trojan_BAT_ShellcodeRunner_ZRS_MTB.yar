
rule Trojan_BAT_ShellcodeRunner_ZRS_MTB{
	meta:
		description = "Trojan:BAT/ShellcodeRunner.ZRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1f 00 06 09 8f ?? 00 00 01 25 71 ?? 00 00 01 20 a1 00 00 00 61 d2 81 ?? 00 00 01 00 09 17 58 0d 09 06 8e 69 fe 04 13 0b 11 0b 2d d5 } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}