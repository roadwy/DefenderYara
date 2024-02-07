
rule Backdoor_BAT_Crysan_ABPE_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //02 00  aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_1 = {30 30 30 30 30 30 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  000000.g.resources
		$a_01_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_3 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  ToBase64String
	condition:
		any of ($a_*)
 
}