
rule TrojanDropper_O97M_Hancitor_EOBZ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 66 20 54 65 72 73 2e 4e 61 6d 65 20 3d 20 22 7a 6f 72 6f 2e 6b 6c 22 20 54 68 65 6e } //01 00  If Ters.Name = "zoro.kl" Then
		$a_01_1 = {44 69 6d 20 6d 67 66 2c 20 75 68 6a 6b 6e 62 2c 20 77 65 72 73 2c 20 71 77 65 64 73 2c 20 66 61 66 61 61 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim mgf, uhjknb, wers, qweds, fafaa As String
		$a_01_2 = {43 61 6c 6c 20 62 76 78 66 63 73 64 28 70 6f 69 64 64 73 29 } //01 00  Call bvxfcsd(poidds)
		$a_01_3 = {46 61 6c 73 65 2c 20 41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 79 6f 75 6b 6e 6f 77 74 68 61 74 74 68 65 67 6f 64 73 6f 66 64 65 61 74 68 6f 6e 6c 79 65 61 74 61 70 70 6c 65 73 3f 22 2c 20 5f } //00 00  False, AddToRecentFiles:=False, PasswordDocument:="doyouknowthatthegodsofdeathonlyeatapples?", _
	condition:
		any of ($a_*)
 
}