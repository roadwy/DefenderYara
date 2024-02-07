
rule Trojan_Win32_Alureon_DQ{
	meta:
		description = "Trojan:Win32/Alureon.DQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 62 6f 74 69 64 3d 25 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d } //01 00  &botid=%s&affid=%s&subid=
		$a_01_1 = {77 73 70 73 65 72 76 65 72 73 } //01 00  wspservers
		$a_01_2 = {74 64 6c 63 6d 64 } //00 00  tdlcmd
	condition:
		any of ($a_*)
 
}