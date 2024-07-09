
rule Ransom_Win32_Cerber_ACB_MTB{
	meta:
		description = "Ransom:Win32/Cerber.ACB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 3b f2 74 ?? 33 c0 39 55 ?? 76 ?? 0f b6 3c 32 8b c8 c1 e1 03 d3 e7 33 df 42 40 83 e0 03 3b 55 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}