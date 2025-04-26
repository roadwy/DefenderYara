
rule TrojanDownloader_Win32_Parkchicers_D{
	meta:
		description = "TrojanDownloader:Win32/Parkchicers.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 75 6e 63 74 69 6f 6e 20 44 6f 77 6e 6c 6f 61 64 52 61 6e 64 6f 6d 55 72 6c 46 69 6c 65 28 29 20 53 54 41 52 54 } //2 function DownloadRandomUrlFile() START
		$a_01_1 = {3d 3d 20 46 2e 49 2e 4e 2e 41 2e 4c 2e 49 2e 5a 2e 41 2e 54 2e 49 2e 4f 2e 4e } //1 == F.I.N.A.L.I.Z.A.T.I.O.N
		$a_01_2 = {3d 3d 20 49 2e 4e 2e 49 2e 54 2e 49 2e 41 2e 4c 2e 49 2e 5a 2e 41 2e 54 2e 49 2e 4f 2e 4e } //1 == I.N.I.T.I.A.L.I.Z.A.T.I.O.N
		$a_01_3 = {45 78 65 63 75 74 65 5f 55 70 64 61 74 65 72 5f } //1 Execute_Updater_
		$a_01_4 = {63 00 6f 00 75 00 6e 00 74 00 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 70 00 68 00 70 00 3f 00 70 00 63 00 3d 00 } //1 count/install.php?pc=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}