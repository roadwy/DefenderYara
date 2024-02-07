
rule TrojanDownloader_O97M_Obfuse_FL{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.FL,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00  Sub Auto_Open()
		$a_01_1 = {63 20 3d 20 22 70 6f 22 20 26 20 22 57 2a 65 72 22 20 26 20 22 73 48 2a 65 6c 22 20 26 20 22 4c 20 2d 57 20 31 20 2d 43 20 70 6f 22 20 26 20 22 77 2a 65 52 73 22 20 26 20 22 68 65 2a 4c 6c 20 28 5b 63 68 61 72 5d 34 35 2b 5b 63 68 61 72 5d 31 30 2a 31 2b 5b 63 68 61 72 5d 31 31 30 2b 5b 63 68 61 72 5d 39 39 29 20 22 20 26 20 78 } //01 00  c = "po" & "W*er" & "sH*el" & "L -W 1 -C po" & "w*eRs" & "he*Ll ([char]45+[char]10*1+[char]110+[char]99) " & x
		$a_01_2 = {53 65 74 20 73 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 43 72 69 70 22 20 26 20 22 74 2e 22 20 26 20 22 53 68 22 20 26 20 22 65 6c 6c 22 29 } //01 00  Set s = CreateObject("WsCrip" & "t." & "Sh" & "ell")
		$a_01_3 = {73 2e 52 75 6e 20 52 65 70 6c 61 63 65 28 63 2c 20 22 2a 22 2c 20 22 22 29 2c 20 30 } //00 00  s.Run Replace(c, "*", ""), 0
	condition:
		any of ($a_*)
 
}