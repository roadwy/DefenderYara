
rule TrojanDownloader_Win32_Istbar_IV{
	meta:
		description = "TrojanDownloader:Win32/Istbar.IV,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 0a 00 00 "
		
	strings :
		$a_02_0 = {ff ff 83 c4 08 a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ff ff 83 c4 08 a3 ?? ?? ?? ?? 68 20 4e 00 00 ff 15 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 05 } //10
		$a_00_1 = {25 73 3f 76 65 72 73 69 6f 6e 3d 25 69 26 6f 6c 64 5f 76 65 72 73 69 6f 6e 3d 25 73 26 69 73 74 73 76 63 3d 25 69 26 69 73 74 72 65 63 6f 76 65 72 3d 25 69 26 73 61 63 63 3d 25 69 26 61 63 63 6f 75 6e 74 5f 69 64 3d 25 69 26 73 6f 66 74 3d 25 73 26 72 76 65 72 73 69 6f 6e 3d 25 73 26 6e 72 3d 25 73 26 6e 64 3d 25 73 26 76 69 6e 66 6f 3d 25 73 } //10 %s?version=%i&old_version=%s&istsvc=%i&istrecover=%i&sacc=%i&account_id=%i&soft=%s&rversion=%s&nr=%s&nd=%s&vinfo=%s
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 49 53 54 } //2 Software\IST
		$a_00_3 = {69 73 74 73 76 63 2e 65 78 65 } //2 istsvc.exe
		$a_00_4 = {53 75 72 66 20 41 63 63 75 72 61 63 79 } //2 Surf Accuracy
		$a_00_5 = {4e 65 76 65 72 49 53 54 73 76 63 } //2 NeverISTsvc
		$a_00_6 = {25 73 26 61 63 3d 25 73 26 73 61 63 3d 25 73 } //1 %s&ac=%s&sac=%s
		$a_00_7 = {63 6f 6e 66 69 67 5f 69 6e 74 65 72 76 61 6c } //1 config_interval
		$a_00_8 = {73 75 62 61 63 63 69 64 } //1 subaccid
		$a_00_9 = {61 63 63 6f 75 6e 74 5f 69 64 } //1 account_id
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=22
 
}