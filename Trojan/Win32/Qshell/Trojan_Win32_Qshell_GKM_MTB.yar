
rule Trojan_Win32_Qshell_GKM_MTB{
	meta:
		description = "Trojan:Win32/Qshell.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 c2 8a a5 08 00 03 55 90 01 01 03 c2 8b 55 90 01 01 31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qshell_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Qshell.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 1e 23 00 00 e8 90 01 04 83 c4 04 8b 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 a1 90 01 04 8d 8c 10 90 01 04 2b 4d 90 01 01 03 0d 90 01 04 89 0d 90 01 04 8b 15 90 01 04 81 ea 1e 23 00 00 89 15 90 01 04 a1 90 01 04 03 45 ac 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 2b d1 89 15 90 01 04 b8 73 00 00 00 85 c0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}