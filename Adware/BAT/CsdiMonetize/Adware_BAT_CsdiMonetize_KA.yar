
rule Adware_BAT_CsdiMonetize_KA{
	meta:
		description = "Adware:BAT/CsdiMonetize.KA,SIGNATURE_TYPE_PEHSTR,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 5a 49 50 50 45 52 2e 70 64 62 } //2 PROZIPPER.pdb
		$a_01_1 = {50 52 4f 5a 49 50 50 45 52 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 PROZIPPER.g.resources
		$a_01_2 = {69 59 70 78 35 54 5a 49 70 78 6a 57 44 56 45 49 6c 33 2e 6d 6b 52 36 65 4e 4f 38 66 31 75 67 37 68 6e 58 36 6c } //1 iYpx5TZIpxjWDVEIl3.mkR6eNO8f1ug7hnX6l
		$a_01_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_4 = {53 74 61 6e 64 41 6c 6f 6e 65 5f 45 6e 6b 77 79 48 6e 4c 36 61 64 64 51 53 52 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 StandAlone_EnkwyHnL6addQSRI.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}