
rule Ransom_Win32_Cerber_YAC_MTB{
	meta:
		description = "Ransom:Win32/Cerber.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 55 9c 8b 45 9c 69 c0 30 09 00 00 89 45 9c 8b 4d f8 33 4d f0 83 c1 02 89 4d f8 8b 55 9c 81 ea 30 09 00 00 89 55 9c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}