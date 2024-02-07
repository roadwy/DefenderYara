
rule Trojan_Win32_VinoSiren_I_dha{
	meta:
		description = "Trojan:Win32/VinoSiren.I!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {41 4e 4f 4e 59 42 52 } //01 00  ANONYBR
		$a_01_1 = {68 4e 4d 57 7a 33 33 63 55 62 47 44 70 39 35 78 7a 72 37 44 56 51 3d 3d } //01 00  hNMWz33cUbGDp95xzr7DVQ==
		$a_01_2 = {6c 49 45 76 38 32 4f 41 42 4f 32 47 70 70 49 3d } //01 00  lIEv82OABO2GppI=
		$a_01_3 = {6a 6f 63 2b 2b 6e 33 64 55 37 65 74 75 70 74 5a 38 71 44 4b 5a 77 3d 3d } //01 00  joc++n3dU7etuptZ8qDKZw==
		$a_01_4 = {72 49 77 34 38 57 72 66 42 66 48 4d 72 70 4a 62 } //01 00  rIw48WrfBfHMrpJb
		$a_01_5 = {6a 35 30 2b 37 31 7a 57 57 4b 65 77 72 34 39 43 77 71 48 53 5a 77 } //01 00  j50+71zWWKewr49CwqHSZw
		$a_01_6 = {67 49 55 6c 2f 57 37 66 61 6f 4b 73 68 62 42 75 35 59 44 70 } //01 00  gIUl/W7faoKshbBu5YDp
		$a_01_7 = {68 4a 73 76 2f 6e 76 57 5a 72 47 4e 71 5a 74 45 31 4a 4d 3d } //00 00  hJsv/nvWZrGNqZtE1JM=
	condition:
		any of ($a_*)
 
}