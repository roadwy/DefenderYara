
rule TrojanProxy_Win32_Delf_AM{
	meta:
		description = "TrojanProxy:Win32/Delf.AM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 61 72 73 65 74 3d 22 6b 6f 69 38 2d 72 22 } //01 00  charset="koi8-r"
		$a_01_1 = {5c 53 65 72 76 69 63 65 50 61 63 6b 46 69 6c 65 73 5c 6d 6d } //01 00  \ServicePackFiles\mm
		$a_00_2 = {6e 73 6c 6f 6f 6b 75 70 20 3c } //01 00  nslookup <
		$a_01_3 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 3b 20 55 3b 20 57 69 6e 64 6f 77 73 20 4e 54 20 35 2e 31 3b 20 72 75 2d 52 55 3b 20 72 76 3a } //01 00  Mozilla/5.0 (Windows; U; Windows NT 5.1; ru-RU; rv:
		$a_00_4 = {6d 61 69 6c 20 65 78 63 68 61 6e 67 65 72 20 3d } //01 00  mail exchanger =
		$a_01_5 = {6d 6d 2e 70 69 64 61 72 } //01 00  mm.pidar
		$a_01_6 = {52 41 4e 44 4f 4d 5f 50 49 43 54 55 52 45 5f 49 44 5f 46 4f 52 5f 41 54 54 41 43 48 4d 45 4e 54 } //00 00  RANDOM_PICTURE_ID_FOR_ATTACHMENT
	condition:
		any of ($a_*)
 
}