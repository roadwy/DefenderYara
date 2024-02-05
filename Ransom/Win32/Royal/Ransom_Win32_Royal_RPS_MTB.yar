
rule Ransom_Win32_Royal_RPS_MTB{
	meta:
		description = "Ransom:Win32/Royal.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 83 c1 01 89 4d f4 8b 55 f4 3b 55 0c 73 27 8b 45 08 03 45 f4 0f b6 08 8b 45 f4 99 be 90 01 04 f7 fe 8b 45 fc 0f b6 14 10 33 ca 8b 45 f8 03 45 f4 88 08 eb c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}