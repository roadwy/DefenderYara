
rule Trojan_BAT_Cerbu_NB_MTB{
	meta:
		description = "Trojan:BAT/Cerbu.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {02 28 5e 00 00 0a 0a 28 ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 2a } //5
		$a_01_1 = {53 63 61 6e 50 72 6f 63 65 73 73 65 73 } //1 ScanProcesses
		$a_01_2 = {72 65 6d 6f 76 65 5f 50 52 4f 43 41 74 } //1 remove_PROCAt
		$a_01_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}