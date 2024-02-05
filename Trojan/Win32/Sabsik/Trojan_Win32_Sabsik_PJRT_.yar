
rule Trojan_Win32_Sabsik_PJRT_{
	meta:
		description = "Trojan:Win32/Sabsik.PJRT!!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 a6 d5 53 51 61 90 b3 bb 66 57 f6 b0 61 90 b3 50 ea d5 5f 91 81 94 38 1d 89 1d f7 55 c1 1b e6 b4 ec 94 7b db } //00 00 
	condition:
		any of ($a_*)
 
}