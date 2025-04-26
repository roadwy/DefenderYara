
rule Trojan_BAT_AZorult_RDA_MTB{
	meta:
		description = "Trojan:BAT/AZorult.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 30 65 61 62 35 38 64 2d 30 32 34 36 2d 34 32 35 66 2d 39 35 65 62 2d 61 35 38 63 30 64 32 61 39 65 65 65 } //2 f0eab58d-0246-425f-95eb-a58c0d2a9eee
		$a_01_1 = {49 6e 73 65 72 74 50 6f 6f 6c } //1 InsertPool
		$a_01_2 = {41 77 61 6b 65 50 6f 6f 6c } //1 AwakePool
		$a_01_3 = {49 6e 63 6c 75 64 65 49 6e 64 65 78 65 72 } //1 IncludeIndexer
		$a_01_4 = {43 6f 6d 70 75 74 65 50 6f 6f 6c } //1 ComputePool
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}