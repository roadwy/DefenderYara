
rule Ransom_Win32_Sodinokibi_SD{
	meta:
		description = "Ransom:Win32/Sodinokibi.SD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 0f b6 c8 89 4d fc 8a 94 0d fc fe ff ff 0f b6 c2 03 c6 0f b6 f0 8a 84 35 fc fe ff ff 88 84 0d fc fe ff ff 88 94 35 fc fe ff ff 0f b6 8c 0d fc fe ff ff } //1
		$a_01_1 = {0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01 75 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}