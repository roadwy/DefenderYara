
rule Trojan_MacOS_Amos_CC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.CC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 55 c0 40 8a 34 0a 40 00 f0 48 8b 7d 90 02 04 0f 0f b6 f8 44 8a 04 3a 44 88 04 0a 40 88 34 3a 48 ff c1 } //1
		$a_03_1 = {49 39 cf 74 ?? 49 8b 36 48 8b 55 a8 8a 14 0a 32 14 0e f6 03 01 48 89 c6 74 ?? 48 8b 73 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}