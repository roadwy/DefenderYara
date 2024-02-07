
rule TrojanDropper_O97M_Hancitor_EOBS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 64 73 61 20 3d 20 22 2e 64 22 } //01 00  fdsa = ".d"
		$a_01_1 = {49 66 20 44 69 72 28 6b 79 74 72 65 77 77 66 20 26 20 66 64 73 20 26 20 22 7a 6f 72 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 } //01 00  If Dir(kytrewwf & fds & "zoro" & fdsa & vssfs)
		$a_01_2 = {43 61 6c 6c 20 70 70 70 78 28 6b 79 74 72 65 77 77 66 20 26 20 66 64 73 20 26 20 22 7a 6f 72 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 } //01 00  Call pppx(kytrewwf & fds & "zoro" & fdsa & vssfs)
		$a_01_3 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 62 76 78 66 63 73 64 22 29 } //00 00  Application.Run("bvxfcsd")
	condition:
		any of ($a_*)
 
}