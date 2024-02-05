
rule Ransom_Win32_Sodinokibi_C{
	meta:
		description = "Ransom:Win32/Sodinokibi.C,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 0f b6 c8 89 4d fc 8a 94 0d fc fe ff ff 0f b6 c2 03 c6 0f b6 f0 8a 84 35 fc fe ff ff 88 84 0d fc fe ff ff 88 94 35 fc fe ff ff 0f b6 8c 0d fc fe ff ff 0f b6 c2 03 c8 8b 45 14 0f b6 c9 8a 8c 0d fc fe ff ff 32 0c 07 88 08 40 89 45 14 8b 45 fc 83 eb 01 } //01 00 
		$a_01_1 = {73 79 73 73 68 61 64 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}