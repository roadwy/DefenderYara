
rule Trojan_Win64_Rhadamanthys_NUC_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 08 81 f1 62 36 00 00 0f b6 40 02 83 f0 34 66 09 } //1
		$a_03_1 = {4c 89 df 4c 31 c7 4c 89 cb 48 29 fb 4c 09 db 4d ?? ?? ?? 4d 31 c3 4c 89 cf 4c 29 df 4c 09 df 48 21 d3 48 21 fb } //3
		$a_01_2 = {0f b7 08 81 f1 62 69 00 00 0f b6 50 02 83 f2 6e 66 09 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1) >=5
 
}