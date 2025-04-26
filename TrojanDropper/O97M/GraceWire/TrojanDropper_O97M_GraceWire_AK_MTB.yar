
rule TrojanDropper_O97M_GraceWire_AK_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4f 70 65 6e 46 6f 72 42 69 6e 61 72 79 4c 6f 63 6b 20 26 20 22 2e 64 6c 22 20 2b 20 22 6c 22 } //1 = OpenForBinaryLock & ".dl" + "l"
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 20 6f 62 6a 46 6f 6c 64 65 72 32 2c 20 22 43 6f 70 79 48 65 72 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 6f 62 6a 46 6f 6c 64 65 72 2e 49 74 65 6d 73 2e 49 74 65 6d 28 22 78 6c 5c 65 22 20 2b 20 22 6d 62 65 64 22 20 2b 20 22 64 69 6e 67 73 5c 6f 6c 65 4f 62 6a 65 63 74 31 2e 62 22 20 2b 20 22 69 6e 22 29 } //1 CallByName objFolder2, "CopyHere", VbMethod, objFolder.Items.Item("xl\e" + "mbed" + "dings\oleObject1.b" + "in")
		$a_01_2 = {3d 20 57 68 65 72 65 54 6f 47 6f 20 2b 20 22 2e 22 20 2b 20 22 7a 69 22 20 2b 20 22 70 22 } //1 = WhereToGo + "." + "zi" + "p"
		$a_01_3 = {43 61 6c 6c 20 53 79 73 74 65 6d 42 75 74 74 6f 6e 53 65 74 74 69 6e 67 73 28 4d 65 2c 20 46 61 6c 73 65 29 } //1 Call SystemButtonSettings(Me, False)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}