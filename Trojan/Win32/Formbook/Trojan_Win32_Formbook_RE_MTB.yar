
rule Trojan_Win32_Formbook_RE_MTB{
	meta:
		description = "Trojan:Win32/Formbook.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 f0 f7 e1 d1 ea 83 e2 fc 8d 04 52 f7 d8 8a 84 06 90 01 04 30 04 33 46 39 f7 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Formbook_RE_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {52 4f 38 00 20 32 0d 0a 00 00 00 00 ff cc 31 00 00 5a 38 a8 dd 00 61 ce 40 8d 46 3d } //01 00 
		$a_01_1 = {49 00 6e 00 64 00 75 00 73 00 74 00 72 00 69 00 61 00 6c 00 65 00 6e 00 6f 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 } //00 00  Industrialenono.exe
	condition:
		any of ($a_*)
 
}