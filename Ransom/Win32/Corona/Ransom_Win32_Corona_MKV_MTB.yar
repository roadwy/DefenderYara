
rule Ransom_Win32_Corona_MKV_MTB{
	meta:
		description = "Ransom:Win32/Corona.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 b8 81 80 80 80 f7 e1 c1 ea 07 8d 44 11 01 8b 4c 24 38 88 04 31 30 06 8b 44 24 2c 47 46 3b f8 72 c4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}