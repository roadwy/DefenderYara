
rule TrojanDownloader_O97M_EncDoc_PDD_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 28 6a 75 31 32 57 62 37 66 64 29 } //1 .Open (ju12Wb7fd)
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 43 68 72 28 28 35 31 20 2d 20 26 48 34 45 20 2b 20 26 48 35 43 29 29 20 26 20 43 68 72 28 28 32 33 20 2b 20 26 48 35 35 29 29 20 2b 20 43 68 72 28 28 26 4f 31 36 37 20 2b 20 26 4f 32 33 33 20 2d 20 26 48 41 36 29 29 20 2b } //1 = Environ(Chr((51 - &H4E + &H5C)) & Chr((23 + &H55)) + Chr((&O167 + &O233 - &HA6)) +
		$a_01_2 = {3d 20 53 70 6c 69 74 28 5a 65 57 47 4a 4a 49 6c 35 38 34 44 4a 71 39 2c 20 43 68 72 28 28 26 4f 31 31 35 20 2d 20 26 4f 31 30 36 20 2b 20 26 4f 31 32 35 29 29 29 } //1 = Split(ZeWGJJIl584DJq9, Chr((&O115 - &O106 + &O125)))
		$a_01_3 = {3d 20 63 61 63 68 65 20 26 20 43 68 72 28 28 26 4f 35 36 20 2b 20 26 4f 35 36 29 29 20 26 20 77 59 52 75 67 72 32 54 28 51 51 4f 46 31 65 39 74 32 4c 69 58 31 29 } //1 = cache & Chr((&O56 + &O56)) & wYRugr2T(QQOF1e9t2LiX1)
		$a_01_4 = {3d 20 52 65 70 6c 61 63 65 28 46 74 42 53 49 42 35 4b 4a 32 4e 30 53 35 2c 20 44 69 72 28 46 74 42 53 49 42 35 4b 4a 32 4e 30 53 35 29 2c 20 4f 34 52 58 4d 49 38 39 34 78 4c 69 33 29 } //1 = Replace(FtBSIB5KJ2N0S5, Dir(FtBSIB5KJ2N0S5), O4RXMI894xLi3)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}