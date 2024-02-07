
rule TrojanDownloader_O97M_EncDoc_KAAP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.KAAP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 63 6d 64 2e 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 78 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 20 2f 63 20 70 6f 77 5e 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 72 73 5e 68 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 6c 6c 2f 57 20 30 31 20 63 5e 75 5e 72 6c } //01 00  = Replace("cmd.participantforgetxparticipantforget /c pow^participantforgetrs^hparticipantforgetll/W 01 c^u^rl
		$a_01_1 = {3a 2f 2f 64 64 6c 38 2e 64 61 74 61 2e 68 75 2f 67 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 74 2f 33 32 38 30 31 30 2f 31 33 33 31 33 38 34 35 2f 45 61 7a 6f 71 6f 2e 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 5e 78 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 20 2d 6f 20 22 20 26 20 77 61 69 74 64 6f 20 26 20 22 3b 22 20 26 20 77 61 69 74 64 6f 2c 20 22 70 61 72 74 69 63 69 70 61 6e 74 66 6f 72 67 65 74 22 2c 20 22 65 22 29 } //00 00  ://ddl8.data.hu/gparticipantforgett/328010/13313845/Eazoqo.participantforget^xparticipantforget -o " & waitdo & ";" & waitdo, "participantforget", "e")
	condition:
		any of ($a_*)
 
}