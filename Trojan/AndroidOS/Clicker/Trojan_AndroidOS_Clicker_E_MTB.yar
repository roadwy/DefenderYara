
rule Trojan_AndroidOS_Clicker_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Clicker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 64 73 63 6c 75 62 70 61 72 74 6e 65 72 73 2e 72 75 2f 70 2e 70 68 70 } //01 00  adsclubpartners.ru/p.php
		$a_00_1 = {26 61 63 74 3d 61 64 76 } //01 00  &act=adv
		$a_00_2 = {63 70 77 2e 30 30 78 66 66 2e 6e 65 74 2f 70 2e 70 68 70 } //01 00  cpw.00xff.net/p.php
		$a_01_3 = {64 6f 49 6e 42 61 63 6b 67 72 6f 75 6e 64 } //01 00  doInBackground
		$a_01_4 = {41 44 44 5f 44 45 56 49 43 45 5f 41 44 4d 49 4e } //00 00  ADD_DEVICE_ADMIN
	condition:
		any of ($a_*)
 
}