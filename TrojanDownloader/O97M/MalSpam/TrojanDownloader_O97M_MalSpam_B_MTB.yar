
rule TrojanDownloader_O97M_MalSpam_B_MTB{
	meta:
		description = "TrojanDownloader:O97M/MalSpam.B!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 20 46 6f 67 6c 69 6f 31 2e 66 66 28 43 65 6c 6c 73 28 75 2c 20 79 7a 29 29 3a } //01 00  + Foglio1.ff(Cells(u, yz)):
		$a_01_1 = {3d 20 41 73 63 28 4c 65 66 74 28 54 72 69 6d 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 70 74 69 6f 6e 29 2c 20 31 29 29 } //01 00  = Asc(Left(Trim(Application.Caption), 1))
		$a_01_2 = {3d 20 22 22 3a 20 53 68 65 6c 6c 20 7a 75 20 26 20 66 72 61 20 26 20 43 65 6c 6c 73 28 79 7a 20 2a 20 32 2c 20 79 7a 20 2f 20 35 29 20 26 20 66 72 61 61 2c 20 6d 73 6f 44 6f 63 49 6e 73 70 65 63 74 6f 72 53 74 61 74 75 73 44 6f 63 4f 6b } //01 00  = "": Shell zu & fra & Cells(yz * 2, yz / 5) & fraa, msoDocInspectorStatusDocOk
		$a_01_3 = {28 52 69 67 68 74 28 66 66 66 2c 20 31 29 20 4d 6f 64 20 32 20 3d 20 30 2c } //01 00  (Right(fff, 1) Mod 2 = 0,
		$a_01_4 = {49 66 20 43 49 6e 74 28 4d 69 64 28 66 66 66 2c 20 66 66 61 20 2a } //00 00  If CInt(Mid(fff, ffa *
	condition:
		any of ($a_*)
 
}