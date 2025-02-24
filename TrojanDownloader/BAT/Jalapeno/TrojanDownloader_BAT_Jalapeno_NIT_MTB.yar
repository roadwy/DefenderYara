
rule TrojanDownloader_BAT_Jalapeno_NIT_MTB{
	meta:
		description = "TrojanDownloader:BAT/Jalapeno.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 65 6d 70 5a 69 70 41 72 63 68 69 76 65 50 61 74 68 } //2 tempZipArchivePath
		$a_01_1 = {64 6f 53 68 61 32 35 36 43 68 65 63 6b } //2 doSha256Check
		$a_00_2 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //2 shell\open\command
		$a_01_3 = {4e 6f 76 61 4c 61 75 6e 63 68 65 72 5f 50 72 6f 63 65 73 73 65 64 42 79 46 6f 64 79 } //1 NovaLauncher_ProcessedByFody
		$a_01_4 = {6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4e 6f 76 61 4c 61 75 6e 63 68 65 72 2e 70 64 62 } //1 obj\Release\NovaLauncher.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}