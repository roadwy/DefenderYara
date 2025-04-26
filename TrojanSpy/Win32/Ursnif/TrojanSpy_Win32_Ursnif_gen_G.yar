
rule TrojanSpy_Win32_Ursnif_gen_G{
	meta:
		description = "TrojanSpy:Win32/Ursnif.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 78 01 2f 75 70 64 74 09 40 80 78 04 00 75 f0 eb 36 83 c0 06 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}