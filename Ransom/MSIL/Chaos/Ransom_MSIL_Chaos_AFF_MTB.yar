
rule Ransom_MSIL_Chaos_AFF_MTB{
	meta:
		description = "Ransom:MSIL/Chaos.AFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 09 0e 04 6f ?? ?? ?? 0a 26 09 0e 05 6f ?? ?? ?? 0a 26 09 0e 06 8c 28 00 00 01 6f ?? ?? ?? 0a 26 02 50 28 ?? ?? ?? 0a 13 04 11 04 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}