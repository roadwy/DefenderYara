
rule Ransom_Win32_Basta_PIE_MTB{
	meta:
		description = "Ransom:Win32/Basta.PIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c3 c0 c8 ?? 90 13 aa 49 90 13 fc 90 13 ac fc 90 13 fc fc 90 13 02 c3 8b d2 90 13 fc fc e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}