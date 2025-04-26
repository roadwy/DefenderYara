
rule TrojanDownloader_Win32_Gulcrypt_B{
	meta:
		description = "TrojanDownloader:Win32/Gulcrypt.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_02_0 = {83 f8 1d 76 ?? 83 f8 1f 73 ?? 83 c0 4a a3 ?? ?? ?? ?? 50 68 90 1b 02 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 0c 68 } //2
		$a_01_1 = {2e 72 75 2f 73 79 73 } //1 .ru/sys
		$a_01_2 = {2e 72 75 2f 72 61 72 } //1 .ru/rar
		$a_01_3 = {63 3a 5c 74 65 65 6d 70 } //1 c:\teemp
		$a_01_4 = {70 69 70 65 63 } //1 pipec
	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}