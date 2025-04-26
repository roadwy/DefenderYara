
rule Trojan_MacOS_Amos_BC_MTB{
	meta:
		description = "Trojan:MacOS/Amos.BC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b 7e 10 48 8b 75 a8 40 8a 34 16 40 32 34 17 f6 03 01 48 89 cf 74 ?? 48 8b 7b 10 40 88 34 17 48 ff c2 } //1
		$a_01_1 = {55 48 89 e5 41 56 53 48 83 ec 10 0f 57 c0 48 83 67 10 00 0f 11 07 48 89 7d e0 c6 45 e8 00 48 85 f6 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}