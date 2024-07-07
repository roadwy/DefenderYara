
rule TrojanDownloader_Win32_Parkchicers_B{
	meta:
		description = "TrojanDownloader:Win32/Parkchicers.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 44 6f 77 6e 6c 6f 61 64 52 61 6e 64 6f 6d 55 72 6c 46 69 6c 65 28 29 20 53 54 41 52 54 } //2 function DownloadRandomUrlFile() START
		$a_01_1 = {31 00 31 00 34 00 2e 00 32 00 30 00 37 00 2e 00 31 00 31 00 32 00 2e 00 31 00 36 00 39 00 } //2 114.207.112.169
		$a_01_2 = {49 2e 4e 2e 53 2e 54 2e 41 2e 4c 2e 4c 2e 45 2e 52 20 45 4e 44 } //1 I.N.S.T.A.L.L.E.R END
		$a_01_3 = {49 6e 73 74 61 6c 6c 65 72 2e 53 65 74 75 70 5f 42 48 4f 5f } //1 Installer.Setup_BHO_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}