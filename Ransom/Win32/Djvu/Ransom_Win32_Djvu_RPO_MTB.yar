
rule Ransom_Win32_Djvu_RPO_MTB{
	meta:
		description = "Ransom:Win32/Djvu.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 7d f0 8b c7 c1 e0 04 89 45 0c 8b 45 dc 01 45 0c 8b 45 f0 03 45 f4 89 45 f8 ff 75 f8 } //00 00 
	condition:
		any of ($a_*)
 
}