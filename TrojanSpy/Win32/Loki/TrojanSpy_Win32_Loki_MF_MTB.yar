
rule TrojanSpy_Win32_Loki_MF_MTB{
	meta:
		description = "TrojanSpy:Win32/Loki.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 3b 44 24 90 02 30 50 e8 90 01 04 b8 90 01 04 31 c9 68 90 01 04 5a 80 34 01 90 01 01 41 39 d1 90 01 02 05 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}