
rule Trojan_Win32_Downloader_CK_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {a1 28 95 4f 00 83 c0 01 a3 28 95 4f 00 81 3d 28 95 4f 00 c8 1e ae 00 73 0d 68 a0 78 4f 00 ff 15 ?? ?? ?? ?? eb da } //1
		$a_00_1 = {15 d2 bd 85 42 0a 81 b4 f0 06 00 83 30 0f 37 d1 d0 e2 7d } //1
		$a_01_2 = {56 69 72 74 75 61 6c 55 6e 6c 6f 63 6b } //1 VirtualUnlock
		$a_81_3 = {61 73 77 43 68 4c 69 63 2e 65 78 65 } //1 aswChLic.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}