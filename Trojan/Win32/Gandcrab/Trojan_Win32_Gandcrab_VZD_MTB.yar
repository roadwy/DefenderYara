
rule Trojan_Win32_Gandcrab_VZD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.VZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 75 6d 61 6a 61 6d 65 70 6f 7a 6f 74 65 72 61 } //01 00  wumajamepozotera
		$a_02_1 = {c0 e1 04 0a 4f 90 01 01 c0 e2 06 0a 57 90 01 01 88 04 1e 46 88 0c 1e 8b 4c 24 90 01 01 46 88 14 1e 83 c5 04 46 3b 29 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}