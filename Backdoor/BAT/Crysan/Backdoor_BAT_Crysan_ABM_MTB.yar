
rule Backdoor_BAT_Crysan_ABM_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ABM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_1 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //01 00  Rfc2898DeriveBytes
		$a_01_2 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_4 = {53 74 75 62 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Stub.g.resources
		$a_01_5 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 53 70 6c 61 73 68 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //01 00  aR3nbf8dQp2feLmk31.SplashForm.resources
		$a_01_6 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //00 00  aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		any of ($a_*)
 
}