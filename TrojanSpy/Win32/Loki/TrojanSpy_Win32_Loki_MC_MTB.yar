
rule TrojanSpy_Win32_Loki_MC_MTB{
	meta:
		description = "TrojanSpy:Win32/Loki.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 e8 28 ff ff ff b8 90 01 04 31 c9 68 90 01 04 5a 80 34 01 90 01 01 41 39 d1 75 90 01 01 05 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}