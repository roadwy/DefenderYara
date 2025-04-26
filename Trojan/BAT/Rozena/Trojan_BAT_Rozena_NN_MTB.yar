
rule Trojan_BAT_Rozena_NN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {09 05 6f 14 00 00 0a 13 04 11 04 08 0e 05 6f ?? 00 00 0a 0a 06 13 06 2b 00 11 06 2a } //3
		$a_01_1 = {53 6e 65 61 6b 79 45 78 65 63 2d 6d 61 73 74 65 72 } //1 SneakyExec-master
		$a_01_2 = {24 36 31 32 35 39 30 61 61 2d 61 66 36 38 2d 34 31 65 36 2d 38 63 65 32 2d 65 38 33 31 66 37 66 65 34 63 63 63 } //1 $612590aa-af68-41e6-8ce2-e831f7fe4ccc
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}