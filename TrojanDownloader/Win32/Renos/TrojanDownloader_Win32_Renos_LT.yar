
rule TrojanDownloader_Win32_Renos_LT{
	meta:
		description = "TrojanDownloader:Win32/Renos.LT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 53 48 4e 41 53 } //01 00  SSHNAS
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 48 61 6e 64 6c 65 } //01 00  SOFTWARE\Microsoft\Handle
		$a_01_2 = {3c 75 72 6c 20 63 72 79 70 74 3d 22 6f 6e 22 20 70 6f 73 74 3d 22 6f 6e 22 3e 68 74 74 70 } //01 00  <url crypt="on" post="on">http
		$a_01_3 = {2e 70 68 70 3f 65 3d 3c 2f 75 72 6c 3e 3c 75 72 6c 20 67 65 74 3d 22 6f 6e 22 3e } //01 00  .php?e=</url><url get="on">
		$a_00_4 = {c7 46 0c 76 54 32 10 } //00 00 
	condition:
		any of ($a_*)
 
}