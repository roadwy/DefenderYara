
rule Ransom_Win32_Conti_PLD_MTB{
	meta:
		description = "Ransom:Win32/Conti.PLD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 98 66 31 44 4d 9a 41 83 f9 2f 73 05 8a 45 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}