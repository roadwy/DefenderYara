
rule Trojan_Win32_KillMBR_AE_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {55 89 e5 83 ec 38 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 08 03 00 00 00 c7 44 24 04 00 00 00 10 c7 04 24 00 40 40 00 a1 90 01 01 61 40 00 ff d0 83 ec 1c 89 45 f4 c7 44 24 10 00 00 00 00 8d 45 f0 89 44 24 0c c7 44 24 08 00 02 00 00 c7 44 24 04 40 40 40 00 8b 45 f4 89 04 24 a1 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}