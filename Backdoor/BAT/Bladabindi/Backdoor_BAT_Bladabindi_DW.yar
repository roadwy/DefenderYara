
rule Backdoor_BAT_Bladabindi_DW{
	meta:
		description = "Backdoor:BAT/Bladabindi.DW,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00 [0-20] 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00 [0-20] 47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 00 6b 65 72 6e 65 6c 33 32 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}