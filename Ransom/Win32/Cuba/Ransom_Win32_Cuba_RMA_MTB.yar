
rule Ransom_Win32_Cuba_RMA_MTB{
	meta:
		description = "Ransom:Win32/Cuba.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 83 45 90 01 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 01 01 c7 45 90 01 01 00 10 00 00 90 00 } //1
		$a_03_1 = {8a a5 08 00 c7 90 02 0a e3 14 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}