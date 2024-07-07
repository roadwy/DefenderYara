
rule Ransom_Win32_Lockbit_HA_MTB{
	meta:
		description = "Ransom:Win32/Lockbit.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 5a 01 66 c7 42 05 c1 c0 88 4a 07 c6 42 08 35 89 42 09 66 c7 42 0d ff e0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}