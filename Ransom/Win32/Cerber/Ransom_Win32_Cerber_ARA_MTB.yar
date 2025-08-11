
rule Ransom_Win32_Cerber_ARA_MTB{
	meta:
		description = "Ransom:Win32/Cerber.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8a 0c 0a 03 d8 a1 6c 06 44 00 32 cb 83 e8 01 88 4c 24 13 75 21 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}