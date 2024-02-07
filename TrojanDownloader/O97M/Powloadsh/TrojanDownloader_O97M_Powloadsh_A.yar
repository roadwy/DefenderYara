
rule TrojanDownloader_O97M_Powloadsh_A{
	meta:
		description = "TrojanDownloader:O97M/Powloadsh.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //01 00  Sub Auto_Open()
		$a_00_1 = {73 70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 } //01 00  spath = Environ("temp") &
		$a_00_2 = {73 70 61 74 68 20 3d 20 73 70 61 74 68 20 26 20 22 2e 70 22 20 26 20 22 73 31 22 } //01 00  spath = spath & ".p" & "s1"
		$a_00_3 = {53 68 65 6c 6c 20 22 70 6f 22 20 26 20 22 77 65 72 73 68 22 20 26 20 22 65 6c 6c 20 2d 45 78 65 22 20 26 20 22 63 75 74 69 6f 6e 50 22 20 26 20 22 6f 6c 69 63 79 20 42 22 20 26 20 22 79 70 61 73 73 20 2d 66 22 20 26 20 22 69 6c 65 20 22 20 26 20 73 70 61 74 68 2c } //00 00  Shell "po" & "wersh" & "ell -Exe" & "cutionP" & "olicy B" & "ypass -f" & "ile " & spath,
	condition:
		any of ($a_*)
 
}