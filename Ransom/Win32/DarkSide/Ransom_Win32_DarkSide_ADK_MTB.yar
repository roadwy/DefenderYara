
rule Ransom_Win32_DarkSide_ADK_MTB{
	meta:
		description = "Ransom:Win32/DarkSide.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 73 52 08 02 5b 5b bb 2d 8c 15 30 06 3a 4b 36 34 a3 aa 06 ad d1 1a b6 1b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}