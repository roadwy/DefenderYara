
rule Ransom_Win32_Lockbit_RPA_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.RPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 54 0d 00 02 d3 8a 5c 15 00 8a 54 1d 00 8a 54 15 00 fe c2 8a 44 15 00 30 07 8a 54 1d 00 86 54 0d 00 88 54 1d 00 fe c1 47 4e 85 f6 75 d2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}