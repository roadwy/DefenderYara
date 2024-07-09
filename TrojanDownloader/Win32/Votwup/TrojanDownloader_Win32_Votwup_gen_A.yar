
rule TrojanDownloader_Win32_Votwup_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Votwup.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 7d fb 01 75 ?? 81 ff b8 0b 00 00 76 ?? 6a 01 6a 00 } //3
		$a_03_1 = {6a 02 6a 00 6a 00 e8 ?? ?? ff ff e8 ?? ?? ff ff 3d b7 00 00 00 75 05 } //3
		$a_01_2 = {6d 73 5f 69 65 } //1 ms_ie
		$a_01_3 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //1 :*:Enabled:
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}