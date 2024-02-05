
rule TrojanSpy_Win32_Ursnif_BS_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 55 90 01 01 03 55 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 8a 0c 31 88 0c 10 8b 55 90 01 01 83 c2 01 89 55 90 01 01 e9 90 00 } //01 00 
		$a_02_1 = {83 ea 15 89 15 90 01 04 a1 90 01 04 03 45 90 01 01 03 05 90 01 04 a3 90 01 04 8b 0d 90 01 04 2b 0d 90 01 04 89 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}