
rule Trojan_AndroidOS_Basbanke_D{
	meta:
		description = "Trojan:AndroidOS/Basbanke.D,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 66 61 76 73 6d 73 20 4f 72 64 65 72 20 42 79 20 69 64 20 44 65 73 63 } //02 00  SELECT * FROM favsms Order By id Desc
		$a_01_1 = {55 50 44 41 54 45 20 43 68 65 63 6b 46 72 65 65 20 53 45 54 20 45 6e 64 43 72 65 61 74 6f 72 3d 27 54 72 75 65 27 20 57 48 45 52 45 20 69 64 20 3d 20 31 } //02 00  UPDATE CheckFree SET EndCreator='True' WHERE id = 1
		$a_01_2 = {55 72 6c 52 65 67 55 73 65 72 } //02 00  UrlRegUser
		$a_01_3 = {6c 62 6c 74 78 74 73 6d 73 } //02 00  lbltxtsms
		$a_01_4 = {6c 62 6c 69 63 6f 6e 73 6d 73 31 } //00 00  lbliconsms1
	condition:
		any of ($a_*)
 
}