
rule VirTool_Win32_Streespyer_A{
	meta:
		description = "VirTool:Win32/Streespyer.A,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {54 00 46 00 4d 00 5f 00 53 00 33 00 43 00 5f 00 4b 00 4c 00 5f 00 4d 00 45 00 4e 00 53 00 } //0a 00  TFM_S3C_KL_MENS
		$a_01_1 = {43 3a 5c 73 33 63 5f 53 69 73 74 65 6d 61 73 5c 53 70 69 61 } //0a 00  C:\s3c_Sistemas\Spia
		$a_01_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 65 2c 20 2f 73 65 6c 65 63 74 2c } //01 00  explorer.exe /e, /select,
		$a_01_3 = {54 00 46 00 4d 00 5f 00 53 00 33 00 43 00 5f 00 53 00 4b 00 32 00 32 00 5f 00 4c 00 4f 00 47 00 49 00 4e 00 } //01 00  TFM_S3C_SK22_LOGIN
		$a_01_4 = {54 00 46 00 4d 00 5f 00 53 00 33 00 43 00 5f 00 4b 00 31 00 34 00 5f 00 4c 00 4f 00 47 00 49 00 4e 00 } //00 00  TFM_S3C_K14_LOGIN
	condition:
		any of ($a_*)
 
}