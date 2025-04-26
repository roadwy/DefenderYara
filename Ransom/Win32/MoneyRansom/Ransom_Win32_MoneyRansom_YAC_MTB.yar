
rule Ransom_Win32_MoneyRansom_YAC_MTB{
	meta:
		description = "Ransom:Win32/MoneyRansom.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 f0 89 b5 90 e0 ff ff 8b 85 88 e1 ff ff 30 8d b7 e0 ff ff 0f b6 d0 0f b7 05 70 c6 49 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}