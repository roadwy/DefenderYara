
rule TrojanDownloader_O97M_MacroConstructor{
	meta:
		description = "TrojanDownloader:O97M/MacroConstructor,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 12 00 00 0a 00 "
		
	strings :
		$a_02_0 = {3d 65 78 63 65 6c 34 6d 61 63 72 6f 73 68 65 65 74 73 90 0a 20 00 73 65 74 90 00 } //0a 00 
		$a_02_1 = {3d 65 78 63 65 6c 34 69 6e 74 6c 6d 61 63 72 6f 73 68 65 65 74 73 90 0a 20 00 73 65 74 90 00 } //0a 00 
		$a_00_2 = {65 78 63 65 6c 34 6d 61 63 72 6f 73 68 65 65 74 73 2e 61 64 64 28 } //0a 00  excel4macrosheets.add(
		$a_00_3 = {65 78 63 65 6c 34 69 6e 74 6c 6d 61 63 72 6f 73 68 65 65 74 73 2e 61 64 64 28 } //0a 00  excel4intlmacrosheets.add(
		$a_00_4 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 75 6e 73 68 65 65 74 73 28 } //0a 00  application.runsheets(
		$a_00_5 = {72 75 6e 28 22 22 26 } //01 00  run(""&
		$a_00_6 = {2e 66 6f 72 6d 75 6c 61 6c 6f 63 61 6c 3d } //01 00  .formulalocal=
		$a_00_7 = {3d 22 3d 65 78 65 63 28 } //01 00  ="=exec(
		$a_00_8 = {3d 22 3d 65 78 65 63 75 74 65 28 } //01 00  ="=execute(
		$a_00_9 = {3d 22 3d 72 65 67 69 73 74 65 72 28 } //01 00  ="=register(
		$a_00_10 = {3d 22 3d 68 61 6c 74 28 29 } //01 00  ="=halt()
		$a_00_11 = {3d 22 3d 63 6f 6e 63 61 74 65 6e 61 74 65 28 } //01 00  ="=concatenate(
		$a_00_12 = {3d 22 3d 63 61 6c 6c 28 } //01 00  ="=call(
		$a_00_13 = {3d 22 3d 72 75 6e 28 } //01 00  ="=run(
		$a_00_14 = {3d 22 3d 66 6f 72 6d 75 6c 61 28 } //01 00  ="=formula(
		$a_00_15 = {3d 22 3d 66 77 72 69 74 65 28 } //01 00  ="=fwrite(
		$a_00_16 = {3d 22 3d 66 69 6c 65 2e 64 65 6c 65 74 65 28 } //01 00  ="=file.delete(
		$a_00_17 = {3d 22 3d 73 65 74 2e 76 61 6c 75 65 28 } //00 00  ="=set.value(
		$a_00_18 = {5d 04 00 00 e3 bd 04 80 5c 25 00 } //00 e6 
	condition:
		any of ($a_*)
 
}