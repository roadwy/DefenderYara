
rule Trojan_Win32_Kryptik_A_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 00 00 00 00 f7 75 e4 89 d1 89 ca 8b 45 08 01 d0 8a 00 31 f0 88 03 ff 45 f4 8b 45 f4 3b 45 10 0f 95 c0 84 c0 } //01 00 
		$a_01_1 = {32 75 63 70 37 58 72 68 30 45 4b 31 39 45 34 } //01 00 
		$a_01_2 = {35 77 35 45 7a 50 43 30 43 31 30 51 72 4b 77 28 } //00 00 
	condition:
		any of ($a_*)
 
}