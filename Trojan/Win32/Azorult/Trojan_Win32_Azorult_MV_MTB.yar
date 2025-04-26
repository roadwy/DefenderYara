
rule Trojan_Win32_Azorult_MV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e0 04 03 ?? 33 [0-03] 33 [0-03] 2b ?? 81 [0-09] 90 18 8b [0-06] 29 [0-03] 83 [0-07] 0f [0-0d] 89 ?? 5f 5e 5d 89 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}