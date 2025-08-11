
rule Ransom_Win32_Blackbasta_EAF_MTB{
	meta:
		description = "Ransom:Win32/Blackbasta.EAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af de 8b d3 c1 ea 10 88 14 01 8b d3 ff 87 84 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}