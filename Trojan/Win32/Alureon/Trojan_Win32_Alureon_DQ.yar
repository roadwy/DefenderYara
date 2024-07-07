
rule Trojan_Win32_Alureon_DQ{
	meta:
		description = "Trojan:Win32/Alureon.DQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 62 6f 74 69 64 3d 25 73 26 61 66 66 69 64 3d 25 73 26 73 75 62 69 64 3d } //1 &botid=%s&affid=%s&subid=
		$a_01_1 = {77 73 70 73 65 72 76 65 72 73 } //1 wspservers
		$a_01_2 = {74 64 6c 63 6d 64 } //1 tdlcmd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}