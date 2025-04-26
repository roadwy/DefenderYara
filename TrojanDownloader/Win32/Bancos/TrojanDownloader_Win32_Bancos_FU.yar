
rule TrojanDownloader_Win32_Bancos_FU{
	meta:
		description = "TrojanDownloader:Win32/Bancos.FU,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 69 74 75 6c 6f 3d } //1 titulo=
		$a_01_1 = {74 65 78 74 6f 3d } //1 texto=
		$a_01_2 = {41 43 37 39 42 32 34 37 44 44 35 41 41 45 37 42 38 30 } //1 AC79B247DD5AAE7B80
		$a_01_3 = {70 72 61 71 75 65 6d 3d } //5 praquem=
		$a_03_4 = {8b c3 8b 08 ff 51 38 68 ?? ?? 47 00 8d 55 ?? 8b [0-02] e8 ?? ?? ff ff ff 75 ?? 68 ?? ?? 47 00 8d 45 ?? ba 03 00 00 00 e8 ?? ?? f8 ff 8b 55 ?? 8b c3 8b 08 ff 51 38 8d 55 ?? 8b ?? 8b 08 ff 51 ?? 8b 4d ?? 8d 45 ?? ba ?? ?? 47 00 e8 ?? ?? ?? ff 8b 55 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_03_4  & 1)*10) >=17
 
}