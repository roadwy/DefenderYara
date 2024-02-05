
rule Trojan_Win32_Qshell_RT_MTB{
	meta:
		description = "Trojan:Win32/Qshell.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ea 18 64 00 00 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 8b 15 90 01 04 2b d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qshell_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Qshell.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 f1 bd 3a 0d 90 01 04 33 c0 89 85 90 01 04 8b 95 90 01 04 3b 95 90 01 04 7f 90 01 01 0f be 0d 90 01 04 3b 0d 90 01 04 8b 85 90 01 04 03 85 90 01 04 89 85 90 01 04 8b 95 90 01 04 8b 8d 90 01 04 31 0a 83 90 01 05 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}