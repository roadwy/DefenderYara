
rule TrojanDownloader_O97M_Dridex_PIL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.PIL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 73 74 46 72 20 3d 20 22 24 22 } //1 listFr = "$"
		$a_01_1 = {49 66 20 68 20 3d 20 70 69 6c 6f 74 70 72 63 20 54 68 65 6e 20 6c 69 73 74 46 72 20 3d 20 22 5d 22 } //1 If h = pilotprc Then listFr = "]"
		$a_01_2 = {53 68 65 65 74 73 28 73 69 6b 29 2e 43 65 6c 6c 73 28 70 69 6c 6f 74 70 72 63 2c 20 73 69 6b 29 2e 4e 61 6d 65 20 3d 20 73 65 6c 65 63 74 65 64 6f 77 6e 20 26 20 22 6e 6f 74 65 22 3a } //1 Sheets(sik).Cells(pilotprc, sik).Name = selectedown & "note":
		$a_01_3 = {49 66 20 49 73 45 6d 70 74 79 28 43 65 6c 6c 73 28 75 2c 20 73 29 29 20 3d 20 46 61 6c 73 65 20 54 68 65 6e 20 6d 20 3d 20 6d 20 26 20 43 68 72 28 43 65 6c 6c 73 28 75 2c 20 73 29 2e 76 61 6c 75 65 20 2d 20 31 29 } //1 If IsEmpty(Cells(u, s)) = False Then m = m & Chr(Cells(u, s).value - 1)
		$a_01_4 = {6a 6f 20 3d 20 39 3a 20 73 64 65 20 3d 20 53 70 6c 69 74 28 6d 2c 20 22 21 22 29 3a 20 42 6f 78 73 69 7a 65 32 20 3d 20 53 70 6c 69 74 28 73 64 65 28 73 69 6b 29 2c 20 6c 69 73 74 46 72 28 70 69 6c 6f 74 70 72 63 29 29 } //1 jo = 9: sde = Split(m, "!"): Boxsize2 = Split(sde(sik), listFr(pilotprc))
		$a_01_5 = {53 68 65 65 74 73 28 73 69 6b 29 2e 43 65 6c 6c 73 28 70 69 6c 6f 74 70 72 63 2c 20 73 69 6b 29 2e 76 61 6c 75 65 20 3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 56 6f 2c 20 22 3f 22 2c 20 48 65 6c 70 50 72 69 6e 74 28 53 70 6c 69 74 28 73 64 65 28 30 29 2c 20 6c 69 73 74 46 72 28 6a 6f 29 29 29 29 } //1 Sheets(sik).Cells(pilotprc, sik).value = "=" & Replace(Vo, "?", HelpPrint(Split(sde(0), listFr(jo))))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}