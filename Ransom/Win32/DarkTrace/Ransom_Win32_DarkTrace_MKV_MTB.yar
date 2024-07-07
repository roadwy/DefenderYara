
rule Ransom_Win32_DarkTrace_MKV_MTB{
	meta:
		description = "Ransom:Win32/DarkTrace.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 90 01 01 88 45 fa 8d 45 b0 50 8d 45 90 01 01 c1 e9 18 50 ff 75 08 88 4d fb ff d2 8b 45 18 83 c4 0c 8b 55 0c 8d 0c 18 8a 44 35 90 01 01 43 30 01 8b 45 18 83 ef 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}