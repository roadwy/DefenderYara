
rule Ransom_Win32_Basta_PIA_MTB{
	meta:
		description = "Ransom:Win32/Basta.PIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d 0c e9 90 0a 05 00 8b 4d 0c 90 13 fc 90 13 8b e4 90 13 90 90 90 13 90 90 90 13 ac 90 13 02 c3 90 13 32 c3 90 13 c0 c8 3f 90 13 aa 90 13 90 90 90 13 fc 90 13 90 90 90 13 8b c9 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}