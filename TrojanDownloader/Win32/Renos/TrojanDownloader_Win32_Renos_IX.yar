
rule TrojanDownloader_Win32_Renos_IX{
	meta:
		description = "TrojanDownloader:Win32/Renos.IX,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 85 08 ff ff ff 0f b6 85 64 fc ff ff 0f b7 85 a4 fd ff ff 0f b7 85 54 fe ff ff 0f b6 85 90 fe ff ff e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_Win32_Renos_IX_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.IX,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 32 34 32 31 31 42 33 2d 41 37 38 41 2d 43 36 41 39 2d 44 33 31 37 2d 37 30 39 37 39 41 43 45 35 30 35 38 } //1 E24211B3-A78A-C6A9-D317-70979ACE5058
		$a_01_1 = {48 41 5f 25 30 38 78 } //1 HA_%08x
		$a_01_2 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 搮汬䐀汬慃啮汮慯乤睯
		$a_01_3 = {77 69 6e 69 6e 65 74 2e 64 6c 6c 3a 3a 48 74 74 70 4f 70 65 6e 52 65 71 75 65 73 74 41 } //1 wininet.dll::HttpOpenRequestA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}