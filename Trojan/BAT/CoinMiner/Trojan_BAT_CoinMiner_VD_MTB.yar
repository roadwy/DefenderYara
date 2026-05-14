
rule Trojan_BAT_CoinMiner_VD_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 70 72 65 6d 65 2e 52 65 73 6f 75 72 63 65 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Supreme.Resource1.resources
		$a_01_1 = {41 6e 74 69 6d 61 6c 77 61 72 65 20 73 65 72 76 69 63 65 20 65 78 65 63 75 74 61 62 6c 65 } //1 Antimalware service executable
		$a_01_2 = {61 70 70 64 61 74 61 20 3d 20 43 75 72 44 69 72 20 2b 20 22 2f 68 6f 73 74 64 6c 2e 65 78 65 22 } //1 appdata = CurDir + "/hostdl.exe"
		$a_01_3 = {73 74 72 69 6e 67 20 63 6f 70 79 20 3d 20 45 6e 76 69 72 6f 6e 6d 65 6e 74 2e 47 65 74 46 6f 6c 64 65 72 50 61 74 68 28 45 6e 76 69 72 6f 6e 6d 65 6e 74 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 2e 41 70 70 6c 69 63 61 74 69 6f 6e 44 61 74 61 29 20 2b 20 40 22 5c 48 69 73 74 6f 72 79 22 } //1 string copy = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\History"
		$a_01_4 = {6d 69 6e 65 72 2e 53 74 61 72 74 28 29 } //1 miner.Start()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}