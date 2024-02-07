
rule Worm_WinNT_Inqtana_C_MTB{
	meta:
		description = "Worm:WinNT/Inqtana.C!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 30 72 6d 73 2e 6c 6f 76 65 2e 61 70 70 6c 65 73 2e 74 67 7a } //01 00  w0rms.love.apples.tgz
		$a_00_1 = {2f 4c 69 62 72 61 72 79 2f 49 6e 70 75 74 4d 61 6e 61 67 65 72 73 2f 49 6e 71 54 61 6e 61 48 61 6e 64 6c 65 72 2f 49 6e 71 54 61 6e 61 48 61 6e 64 6c 65 72 2e 62 75 6e 64 6c 65 } //01 00  /Library/InputManagers/InqTanaHandler/InqTanaHandler.bundle
		$a_00_2 = {2f 43 6f 6e 74 65 6e 74 73 2f 4d 61 63 4f 53 2f 49 6e 71 54 61 6e 61 48 61 6e 64 6c 65 72 } //00 00  /Contents/MacOS/InqTanaHandler
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}