
rule Trojan_Win32_Guloader_AC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AC!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a8 cb a1 72 d1 cb a1 72 86 93 a3 72 f9 09 a3 72 01 cc a1 72 0c cc a1 72 31 68 a4 72 29 19 a2 72 62 72 a4 72 88 be a0 72 ba 02 a3 72 41 09 a3 72 } //01 00 
		$a_01_1 = {20 e2 36 4b b8 42 4d 4b 00 00 10 75 d5 a3 02 42 2c f5 8d 4b } //00 00 
	condition:
		any of ($a_*)
 
}