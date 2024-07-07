
rule Ransom_Win32_Basta_AMMF_MTB{
	meta:
		description = "Ransom:Win32/Basta.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 41 48 8b 9e 80 00 00 00 a1 90 01 04 0f af da 8b 88 84 00 00 00 8b 86 b8 00 00 00 8b d3 c1 ea 08 88 14 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}