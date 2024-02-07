
rule TrojanSpy_Linux_FinSpy_VB_MTB{
	meta:
		description = "TrojanSpy:Linux/FinSpy.VB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {2f 66 69 6e 73 70 79 90 02 10 2e 63 66 67 90 00 } //01 00 
		$a_01_1 = {2f 66 69 6e 5f 63 72 79 70 74 6f 2e 63 70 70 } //01 00  /fin_crypto.cpp
		$a_01_2 = {46 69 6e 53 70 79 56 32 } //01 00  FinSpyV2
		$a_01_3 = {2f 75 73 72 2f 6c 6f 63 61 6c 2f 66 69 6e 66 6c 79 2f 63 66 67 2f } //01 00  /usr/local/finfly/cfg/
		$a_01_4 = {46 49 4e 5f 54 41 52 47 45 54 } //01 00  FIN_TARGET
		$a_01_5 = {2e 66 69 6e 5f 70 61 73 73 77 64 } //01 00  .fin_passwd
		$a_00_6 = {53 50 4b 2e 70 65 6d } //00 00  SPK.pem
		$a_00_7 = {5d 04 00 } //00 e8 
	condition:
		any of ($a_*)
 
}