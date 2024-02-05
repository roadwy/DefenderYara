
rule Trojan_Win32_Qshell_RB_MTB{
	meta:
		description = "Trojan:Win32/Qshell.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {01 02 68 3b 11 00 00 6a 00 e8 90 01 04 8b d8 8b 45 90 01 01 05 8a a5 08 00 03 45 90 01 01 03 d8 68 3b 11 00 00 6a 00 e8 90 01 04 03 d8 8b 45 e0 31 18 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}