
rule Trojan_Win32_Nufsys_A_dha{
	meta:
		description = "Trojan:Win32/Nufsys.A!dha,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 65 63 68 6f 7c 73 65 74 2f 70 3d 22 4d 5a 22 } //0a 00  cmd /c echo|set/p="MZ"
		$a_01_1 = {73 79 73 66 75 6e } //00 00  sysfun
	condition:
		any of ($a_*)
 
}