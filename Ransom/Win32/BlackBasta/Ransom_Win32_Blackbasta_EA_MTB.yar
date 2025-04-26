
rule Ransom_Win32_Blackbasta_EA_MTB{
	meta:
		description = "Ransom:Win32/Blackbasta.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d3 c1 ea 10 8b 88 84 00 00 00 8b 86 b8 00 00 00 88 14 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}