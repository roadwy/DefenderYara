
rule TrojanDownloader_O97M_Obfuse_LH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.LH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 22 25 61 70 70 64 61 74 61 25 5c 6a 65 74 36 36 33 33 22 22 22 } //01 00  ""%appdata%\jet6633"""
		$a_01_1 = {2b 20 22 5c 41 70 22 20 2b 20 22 70 44 22 20 2b 20 22 61 22 20 2b 20 22 74 61 5c 52 22 20 2b 20 22 6f 61 22 20 2b 20 22 6d 69 22 20 2b 20 22 6e 67 22 20 26 20 22 5c 22 } //01 00  + "\Ap" + "pD" + "a" + "ta\R" + "oa" + "mi" + "ng" & "\"
		$a_01_2 = {26 20 22 27 2c 20 27 25 41 50 50 44 41 54 41 25 5c 6a 65 27 20 2b 20 27 74 36 36 27 20 2b 20 27 33 33 5c 61 73 27 20 2b 20 27 70 6f 74 27 20 2b 20 27 6f 2e 65 78 27 20 2b 20 27 65 27 29 22 20 20 27 72 65 67 65 78 2e 65 78 65 } //01 00  & "', '%APPDATA%\je' + 't66' + '33\as' + 'pot' + 'o.ex' + 'e')"  'regex.exe
		$a_01_3 = {2e 54 61 67 20 2b } //01 00  .Tag +
		$a_01_4 = {50 75 74 20 23 31 } //00 00  Put #1
	condition:
		any of ($a_*)
 
}