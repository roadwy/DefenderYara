
rule TrojanSpy_Win32_Ursnif_AA_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {05 60 c2 2e 02 a3 90 01 04 8b 0d 90 01 04 03 4d e4 8b 15 90 01 04 89 91 25 ef ff ff 8b 45 ec 69 c0 f5 1b 00 00 0f b7 4d e8 0f af c1 66 89 45 e8 0f b7 55 e8 6b d2 39 03 15 90 01 04 8b 45 ec 2b c2 89 45 ec e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}