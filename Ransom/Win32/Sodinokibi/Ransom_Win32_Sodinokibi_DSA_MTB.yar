
rule Ransom_Win32_Sodinokibi_DSA_MTB{
	meta:
		description = "Ransom:Win32/Sodinokibi.DSA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 8c 0d fc fe ff ff 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}