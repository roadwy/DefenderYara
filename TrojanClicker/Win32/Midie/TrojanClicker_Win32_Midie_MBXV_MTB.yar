
rule TrojanClicker_Win32_Midie_MBXV_MTB{
	meta:
		description = "TrojanClicker:Win32/Midie.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {98 18 40 00 13 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 01 00 e9 00 00 00 48 14 40 00 e8 14 40 00 ec 10 40 00 78 00 00 00 80 00 00 00 87 00 00 00 88 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}