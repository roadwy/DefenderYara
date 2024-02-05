
rule TrojanSpy_Win32_Noon_KH_MTB{
	meta:
		description = "TrojanSpy:Win32/Noon.KH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 33 c9 89 bd 90 01 04 85 db 74 1b 8d 49 90 01 01 8a 81 90 01 04 30 04 3a 83 f9 90 01 03 33 c9 90 01 02 41 42 3b d3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}