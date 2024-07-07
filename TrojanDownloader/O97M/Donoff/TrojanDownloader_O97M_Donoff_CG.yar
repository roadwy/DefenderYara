
rule TrojanDownloader_O97M_Donoff_CG{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CG,SIGNATURE_TYPE_MACROHSTR_EXT,ffffff90 01 ffffff90 01 05 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 43 6c 6f 73 65 28 29 } //100 Public Sub Document_Close()
		$a_00_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 43 61 6c 6c 42 79 4e 61 6d 65 28 } //100 CallByName(CallByName(
		$a_00_2 = {22 54 45 47 22 2c } //100 "TEG",
		$a_00_3 = {22 6e 65 70 4f 22 } //100 "nepO"
		$a_00_4 = {22 41 2d 72 65 73 55 74 6e 65 67 } //100 "A-resUtneg
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*100) >=400
 
}
rule TrojanDownloader_O97M_Donoff_CG_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CG,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {64 28 31 35 2c 20 31 39 2c 20 22 6e 65 70 4f 22 29 2c 20 31 2c 20 64 28 31 34 2c 20 33 32 2c 20 22 54 45 47 22 29 2c 20 64 28 32 30 32 2c 20 35 32 37 2c 20 22 2e 70 69 6f 63 2e 68 3a 6f 6e 6e 6c 6f 2f 67 2f 69 34 6e 70 63 69 6f 6f 63 6b 75 73 66 36 69 74 2f 6c 63 72 2e 75 6c 6e 66 65 62 74 2f 6f 67 74 73 22 29 2c 20 46 61 6c 73 65 } //1 d(15, 19, "nepO"), 1, d(14, 32, "TEG"), d(202, 527, ".pioc.h:onnlo/g/i4npcioockusf6it/lcr.ulnfebt/ogts"), False
		$a_00_1 = {64 28 31 35 2c 20 31 39 2c 20 22 6e 65 70 4f 22 29 2c 20 31 2c 20 64 28 31 34 2c 20 33 32 2c 20 22 54 45 47 22 29 2c 20 64 28 31 37 31 2c 20 32 30 39 2c 20 22 70 74 74 68 65 6d 2f 79 74 69 63 2f 31 2e 32 76 2f 70 69 6f 65 67 2f 6d 6f 63 2e 64 6e 69 6d 78 61 6d 2e 77 77 77 2f 2f 3a 73 22 29 2c 20 46 61 6c 73 65 } //1 d(15, 19, "nepO"), 1, d(14, 32, "TEG"), d(171, 209, "ptthem/ytic/1.2v/pioeg/moc.dnimxam.www//:s"), False
		$a_00_2 = {57 48 70 71 73 35 57 48 70 69 74 52 75 74 2e 69 74 2e 6e 74 65 65 2e 31 6e 74 } //1 WHpqs5WHpitRut.it.ntee.1nt
		$a_00_3 = {37 74 74 37 30 6d 6d 34 2e 70 70 } //1 7tt70mm4.pp
		$a_00_4 = {6f 76 65 46 65 53 69 54 61 6c } //1 oveFeSiTal
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}