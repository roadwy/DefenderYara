
rule Trojan_Win32_Zenpack_RE_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 62 f8 9f 88 83 c4 04 8a 06 83 c6 01 68 9a 89 70 2d 83 c4 04 32 02 83 ec 04 c7 04 24 f3 29 e6 c5 83 c4 04 88 07 83 c7 01 42 } //01 00 
		$a_01_1 = {50 6e 68 75 62 67 79 45 63 74 79 76 } //00 00 
	condition:
		any of ($a_*)
 
}