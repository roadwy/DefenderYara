
rule Trojan_Win64_Farfli_ADC_MTB{
	meta:
		description = "Trojan:Win64/Farfli.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b ca 41 f7 e2 80 c1 36 43 30 0c 03 c1 ea 03 8d 0c 92 03 c9 44 3b d1 4d 0f 44 cf 41 ff c2 49 ff c3 44 3b d7 7c } //4
		$a_01_1 = {41 0f b6 0c 29 4c 8b 43 10 49 ff c1 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}