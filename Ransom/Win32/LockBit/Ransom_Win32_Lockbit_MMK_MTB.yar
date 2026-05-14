
rule Ransom_Win32_Lockbit_MMK_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.MMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d1 89 ef 31 f1 30 0c 03 c1 e7 0b 31 ef 89 fa c1 ea 08 31 fa 89 cf c1 ef 13 31 ca 31 fa 89 df 30 54 03 01 89 f5 8b 74 24 04 83 c0 02 39 04 24 75 b5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}