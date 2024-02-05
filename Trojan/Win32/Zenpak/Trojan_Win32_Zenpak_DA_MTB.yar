
rule Trojan_Win32_Zenpak_DA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {f7 f9 89 55 d0 8b 55 f0 8b 75 d4 0f b6 14 16 8b 75 d0 8b 7d e8 0f b6 34 37 31 f2 88 d7 8b 55 f0 8b 75 dc 88 3c 16 8b 45 f0 05 01 00 00 00 89 45 f0 8b 45 d8 39 45 f0 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}