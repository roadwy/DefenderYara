
rule TrojanDropper_Win32_Bunitu_MY_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 d9 8b 95 90 01 04 0f be 02 2b c1 8b 8d 90 01 04 88 01 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_1 = {33 d0 8b ca 8b c1 c7 05 90 01 08 01 05 90 09 11 00 a1 90 01 04 8b 15 90 01 04 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}