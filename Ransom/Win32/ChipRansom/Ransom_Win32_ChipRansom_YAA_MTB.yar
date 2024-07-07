
rule Ransom_Win32_ChipRansom_YAA_MTB{
	meta:
		description = "Ransom:Win32/ChipRansom.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 52 ff 15 90 01 04 32 5d e7 6a 18 88 5d d0 e8 90 01 04 83 c4 04 89 45 ec 89 7d fc 3b c7 74 90 00 } //1
		$a_03_1 = {72 96 8b 15 90 01 04 85 d2 75 90 01 01 8b 45 cc 8b 4d e0 3b c8 7e 90 01 01 6b c9 45 03 4d e8 8b f0 0f af f0 03 ce 89 4d e8 8b 45 dc 40 3b 45 0c 89 45 dc 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}