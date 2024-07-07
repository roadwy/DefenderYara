
rule Backdoor_BAT_AsyncRAT_NRZ_MTB{
	meta:
		description = "Backdoor:BAT/AsyncRAT.NRZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 08 28 3d 00 00 0a 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 06 18 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 90 01 01 00 00 0a 0b de 11 90 00 } //5
		$a_01_1 = {63 69 7a 62 63 6b 6a 2e 52 65 73 6f 75 72 63 65 73 } //1 cizbckj.Resources
		$a_01_2 = {58 42 69 6e 64 65 72 2d 4f 75 74 70 75 74 } //1 XBinder-Output
		$a_01_3 = {57 69 6e 64 6f 77 73 50 72 69 6e 63 69 70 61 6c } //1 WindowsPrincipal
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}