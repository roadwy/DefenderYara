
rule Ransom_Win32_ContiCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b f7 53 0f b6 06 46 85 c0 74 90 01 01 51 90 01 01 c7 04 e4 90 01 04 59 bb 90 01 04 8b d6 c7 45 fc 90 01 04 d3 c0 8a fc 8a e6 d3 cb ff 4d 90 01 01 75 90 02 04 8b c3 90 02 04 aa 49 75 90 00 } //01 00 
		$a_03_1 = {8b cf 23 4d 90 01 01 75 90 01 01 46 8b 45 90 01 01 0f b6 1c 30 8b 55 90 01 01 d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}