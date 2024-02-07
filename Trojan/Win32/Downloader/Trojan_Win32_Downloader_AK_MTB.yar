
rule Trojan_Win32_Downloader_AK_MTB{
	meta:
		description = "Trojan:Win32/Downloader.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 2e 39 31 39 79 69 2e 63 6f 6d 2f 70 63 5f 73 69 6e 67 6c 65 2f 39 65 5f 64 69 6e 67 64 69 6e 67 77 65 61 74 68 65 72 5f 49 44 3d 36 34 37 37 30 2c 44 44 57 3d 36 34 37 37 30 2c 2e 65 78 65 } //01 00  dl.919yi.com/pc_single/9e_dingdingweather_ID=64770,DDW=64770,.exe
		$a_01_1 = {63 3a 5c 39 65 5f 64 69 6e 67 64 69 6e 67 77 65 61 74 68 65 72 5f 49 44 3d 36 34 37 37 30 2c 44 44 57 3d 36 34 37 37 30 2c 2e 65 78 65 } //01 00  c:\9e_dingdingweather_ID=64770,DDW=64770,.exe
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_3 = {49 6e 74 65 72 6e 65 74 43 72 61 63 6b 55 72 6c 41 } //00 00  InternetCrackUrlA
	condition:
		any of ($a_*)
 
}