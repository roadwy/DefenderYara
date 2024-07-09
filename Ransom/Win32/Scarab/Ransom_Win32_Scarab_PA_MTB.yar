
rule Ransom_Win32_Scarab_PA_MTB{
	meta:
		description = "Ransom:Win32/Scarab.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 ?? bb 00 00 00 00 23 d3 21 5d fc ff 75 fc 81 04 24 08 00 00 00 8f 45 fc d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 55 33 2c 24 33 eb 83 e0 00 03 c5 5d aa 49 75 } //1
		$a_00_1 = {a4 49 75 fc 33 c9 0b 0c 24 83 c4 04 33 ff 8b 3c 24 83 ec fc 6a 00 89 04 24 33 c0 33 c7 8b f0 58 56 29 34 24 31 1c 24 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}