
rule Trojan_BAT_Marsilia_AYB_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 69 00 72 00 61 00 63 00 75 00 6c 00 69 00 78 00 2e 00 72 00 75 00 } //2 miraculix.ru
		$a_01_1 = {6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 34 2e 70 64 62 } //1 obj\x86\Release\WindowsFormsApplication4.pdb
		$a_01_2 = {24 34 38 31 31 63 38 61 33 2d 39 37 63 65 2d 34 61 65 38 2d 38 61 37 36 2d 37 35 31 65 31 38 64 62 62 38 61 62 } //1 $4811c8a3-97ce-4ae8-8a76-751e18dbb8ab
		$a_00_3 = {64 00 73 00 5f 00 61 00 70 00 64 00 61 00 74 00 65 00 2e 00 65 00 78 00 65 00 } //1 ds_apdate.exe
		$a_00_4 = {64 00 69 00 76 00 73 00 69 00 67 00 5f 00 74 00 61 00 73 00 6b 00 6c 00 69 00 73 00 74 00 2e 00 74 00 78 00 74 00 } //1 divsig_tasklist.txt
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=6
 
}