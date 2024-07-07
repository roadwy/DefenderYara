
rule Ransom_Win32_Sodinokibi_DSB_MTB{
	meta:
		description = "Ransom:Win32/Sodinokibi.DSB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 04 02 8b 55 0c 0f b6 c9 03 c8 0f b6 c1 8b 4d 08 8a 04 08 32 04 1a 88 03 43 8b 45 10 89 5d 14 83 ef 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}