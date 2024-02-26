
rule Trojan_MacOS_Amos_F_MTB{
	meta:
		description = "Trojan:MacOS/Amos.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 65 73 6b 77 61 6c 6c 65 74 73 2f 45 78 6f 64 75 73 2f } //01 00  deskwallets/Exodus/
		$a_00_1 = {46 69 6c 65 47 72 61 62 62 65 72 2f 4e 6f 74 65 53 74 6f 72 65 2e 73 71 6c 69 74 65 } //01 00  FileGrabber/NoteStore.sqlite
		$a_00_2 = {2f 2e 63 6f 6e 66 69 67 2f 66 69 6c 65 7a 69 6c 6c 61 2f 72 65 63 65 6e 74 73 65 72 76 65 72 73 2e 78 6d 6c } //00 00  /.config/filezilla/recentservers.xml
	condition:
		any of ($a_*)
 
}