
rule Trojan_Win64_DllInject_NTA_MTB{
	meta:
		description = "Trojan:Win64/DllInject.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 80 e3 20 41 80 fb 01 66 44 11 d1 48 83 c2 02 49 83 c1 30 49 39 d0 } //3
		$a_01_1 = {48 8d 14 52 0f b6 54 d0 12 80 e2 20 80 fa 01 66 83 d1 00 48 89 da 48 c1 e2 10 48 c1 fa 10 48 8d 14 52 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}