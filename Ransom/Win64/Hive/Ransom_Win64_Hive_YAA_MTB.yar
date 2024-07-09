
rule Ransom_Win64_Hive_YAA_MTB{
	meta:
		description = "Ransom:Win64/Hive.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 6c 11 08 48 33 6c 08 08 48 89 ac 0c ?? ?? ?? ?? 48 83 c1 08 48 83 f9 28 72 } //5
		$a_03_1 = {0f 92 c2 c0 e2 ?? 08 ca 8a 8c 04 ?? ?? ?? ?? 8d 59 ?? 80 fb ?? 0f 92 c3 c0 e3 ?? 08 cb 48 ?? ?? 38 da 74 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1) >=6
 
}