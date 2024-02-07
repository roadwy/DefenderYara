
rule TrojanSpy_Win32_Ranbyus_A{
	meta:
		description = "TrojanSpy:Win32/Ranbyus.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 c3 ff fb ff ff c1 eb 0a 43 8b c3 69 c0 00 fc ff ff } //02 00 
		$a_03_1 = {eb 02 d1 e8 4a 75 ee 89 04 8d 90 09 05 00 35 90 00 } //01 00 
		$a_01_2 = {2e 69 42 61 6e 6b 2a } //01 00  .iBank*
		$a_01_3 = {3c 66 6f 72 6d 5c 73 61 63 74 69 6f 6e } //01 00  <form\saction
		$a_01_4 = {70 72 66 78 } //00 00  prfx
	condition:
		any of ($a_*)
 
}