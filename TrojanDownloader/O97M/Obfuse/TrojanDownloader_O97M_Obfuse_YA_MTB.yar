
rule TrojanDownloader_O97M_Obfuse_YA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.YA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {5e 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 24 4d 6f 3d 40 28 } //1 ^owershell.exe $Mo=@(
		$a_02_1 = {6d 69 7a 20 3d 20 52 65 70 6c 61 63 65 28 [0-12] 2c 20 22 5e 22 2c 20 22 50 22 29 } //1
		$a_00_2 = {6f 62 6a 31 2e 52 75 6e 20 73 20 26 20 6d 69 7a } //1 obj1.Run s & miz
		$a_00_3 = {24 74 3d 5b 53 79 73 74 65 6d 2e 54 65 78 74 2e 45 6e 63 6f 64 69 6e 67 5d 3a 3a 41 53 43 49 49 2e 47 65 74 53 74 72 69 6e 67 28 24 4d 6f 29 7c 49 45 58 } //1 $t=[System.Text.Encoding]::ASCII.GetString($Mo)|IEX
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}