
rule Backdoor_BAT_Bladabindi_SN_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {33 33 33 33 33 33 33 33 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 33333333.g.resources
		$a_81_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_81_2 = {7b 31 31 31 31 31 2d 32 32 32 32 32 2d 34 30 30 30 31 2d 30 30 30 30 31 7d } //1 {11111-22222-40001-00001}
		$a_81_3 = {33 33 33 33 33 33 33 33 2e 65 78 65 } //1 33333333.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}