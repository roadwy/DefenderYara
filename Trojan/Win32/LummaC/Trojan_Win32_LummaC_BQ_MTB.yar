
rule Trojan_Win32_LummaC_BQ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.BQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e4 99 f7 7d e0 8b 45 e4 8b 4d ec 8b 75 dc 8b 04 81 33 04 96 8b 4d e4 8b 55 ec 89 04 8a e9 } //4
		$a_01_1 = {0f b6 55 f4 03 04 91 5e 8b 4d fc 33 cd e8 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}