
rule Trojan_Win32_Downloader_CK_MTB{
	meta:
		description = "Trojan:Win32/Downloader.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {a1 28 95 4f 00 83 c0 01 a3 28 95 4f 00 81 3d 28 95 4f 00 c8 1e ae 00 73 0d 68 a0 78 4f 00 ff 15 90 01 04 eb da 90 00 } //01 00 
		$a_00_1 = {15 d2 bd 85 42 0a 81 b4 f0 06 00 83 30 0f 37 d1 d0 e2 7d } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 55 6e 6c 6f 63 6b } //01 00  VirtualUnlock
		$a_81_3 = {61 73 77 43 68 4c 69 63 2e 65 78 65 } //00 00  aswChLic.exe
	condition:
		any of ($a_*)
 
}