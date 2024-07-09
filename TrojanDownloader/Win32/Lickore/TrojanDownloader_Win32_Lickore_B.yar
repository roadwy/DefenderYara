
rule TrojanDownloader_Win32_Lickore_B{
	meta:
		description = "TrojanDownloader:Win32/Lickore.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ba 03 00 00 00 e8 ?? ?? ?? ?? 8b 55 ?? b8 ?? ?? ?? ?? e8 [0-10] ff [0-05] 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 ?? ba 03 00 00 00 } //1
		$a_00_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_00_2 = {64 6f 77 6e 2e 74 6d 71 72 68 6b 73 2e 63 6f 6d 2f 64 69 73 74 } //1 down.tmqrhks.com/dist
		$a_03_3 = {54 52 41 43 45 [0-10] 50 55 54 [0-10] 43 4f 4e 4e 45 43 54 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}