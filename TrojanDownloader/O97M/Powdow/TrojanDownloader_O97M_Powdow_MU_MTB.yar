
rule TrojanDownloader_O97M_Powdow_MU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.MU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 67 68 69 6f 67 68 69 77 67 68 69 6e 67 68 69 4c 67 68 69 6f 67 68 69 41 67 68 69 64 67 68 69 46 67 68 69 69 67 68 69 4c 67 68 69 45 } //01 00  dghioghiwghinghiLghioghiAghidghiFghiighiLghiE
		$a_00_1 = {68 67 68 69 74 67 68 69 74 67 68 69 70 67 68 69 3a 67 68 69 2f 67 68 69 2f 67 68 69 75 67 68 69 6e 67 68 69 69 67 68 69 74 67 68 69 74 67 68 69 6f 67 68 69 67 67 68 69 72 67 68 69 65 67 68 69 61 67 68 69 73 67 68 69 2e 67 68 69 74 67 68 69 6f 67 68 69 70 67 68 69 2f 67 68 69 73 67 68 69 65 67 68 69 61 67 68 69 72 67 68 69 63 67 68 69 68 67 68 69 2e 67 68 69 70 67 68 69 68 67 68 69 70 } //01 00  hghitghitghipghi:ghi/ghi/ghiughinghiighitghitghioghigghirghieghiaghisghi.ghitghioghipghi/ghisghieghiaghirghicghihghi.ghipghihghip
		$a_00_2 = {25 67 68 69 41 67 68 69 70 67 68 69 50 67 68 69 44 67 68 69 61 67 68 69 54 67 68 69 61 67 68 69 25 67 68 69 2e 67 68 69 45 67 68 69 58 67 68 69 65 67 68 69 27 67 68 69 29 } //01 00  %ghiAghipghiPghiDghiaghiTghiaghi%ghi.ghiEghiXghieghi'ghi)
		$a_00_3 = {67 68 69 53 67 68 69 54 67 68 69 41 67 68 69 72 67 68 69 54 67 68 69 2d 67 68 69 70 67 68 69 72 67 68 69 4f 67 68 69 43 67 68 69 45 67 68 69 53 67 68 69 53 67 68 69 } //01 00  ghiSghiTghiAghirghiTghi-ghipghirghiOghiCghiEghiSghiSghi
		$a_00_4 = {43 67 68 69 4d 67 68 69 64 67 68 69 2e 67 68 69 65 67 68 69 78 67 68 69 45 67 68 69 20 67 68 69 2f 67 68 69 63 67 68 69 } //01 00  CghiMghidghi.ghieghixghiEghi ghi/ghicghi
		$a_00_5 = {67 68 69 50 67 68 69 4f 67 68 69 57 67 68 69 45 67 68 69 72 67 68 69 73 67 68 69 68 67 68 69 65 67 68 69 6c 67 68 69 6c 67 68 69 2e 67 68 69 65 67 68 69 78 67 68 69 45 67 68 69 } //00 00  ghiPghiOghiWghiEghirghisghihghieghilghilghi.ghieghixghiEghi
	condition:
		any of ($a_*)
 
}