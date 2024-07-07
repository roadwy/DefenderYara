
rule TrojanDownloader_BAT_Genmaldow_U{
	meta:
		description = "TrojanDownloader:BAT/Genmaldow.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 52 65 70 6c 61 63 65 28 22 20 22 2c 20 22 22 29 2e 52 65 70 6c 61 63 65 28 22 5c 5c 6e 22 2c 20 22 22 29 2e 53 70 6c 69 74 28 27 7c 27 29 3b } //1 .Replace(" ", "").Replace("\\n", "").Split('|');
		$a_01_1 = {50 61 74 68 2e 43 6f 6d 62 69 6e 65 28 45 6e 76 69 72 6f 6e 6d 65 6e 74 2e 47 65 74 46 6f 6c 64 65 72 50 61 74 68 28 45 6e 76 69 72 6f 6e 6d 65 6e 74 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 2e 41 70 70 6c 69 63 61 74 69 6f 6e 44 61 74 61 29 2c 20 22 4a 61 76 61 22 29 } //1 Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Java")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}