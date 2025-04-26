
rule Ransom_Win32_Egregor_YZ_MTB{
	meta:
		description = "Ransom:Win32/Egregor.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 08 8b 4d b8 0f b6 4c 0d bc 31 c8 88 c2 [0-ff] 8b 45 10 8b 4d b8 88 14 08 } //5
		$a_01_1 = {8b 4d b8 0f b6 4c 0d bc 31 c8 88 c2 8b 45 10 8b 4d b8 88 14 08 8b 45 b8 83 c0 01 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}