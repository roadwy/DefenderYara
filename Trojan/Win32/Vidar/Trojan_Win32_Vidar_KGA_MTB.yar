
rule Trojan_Win32_Vidar_KGA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 8a 44 04 40 30 04 29 45 3b ac 24 4c 02 00 00 7c a0 } //00 00 
	condition:
		any of ($a_*)
 
}