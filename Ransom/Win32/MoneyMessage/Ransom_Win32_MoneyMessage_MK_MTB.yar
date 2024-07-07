
rule Ransom_Win32_MoneyMessage_MK_MTB{
	meta:
		description = "Ransom:Win32/MoneyMessage.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 99 f7 f9 33 74 d5 90 01 01 33 7c d5 90 01 01 8b 95 90 01 04 8b c2 31 30 8d 40 90 01 01 31 78 90 01 01 83 e9 90 01 01 75 90 01 01 83 c2 90 01 01 8d 71 90 01 01 43 89 95 90 01 04 83 ad 90 01 05 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}