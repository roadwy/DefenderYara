
rule Trojan_AndroidOS_SpamSold_A{
	meta:
		description = "Trojan:AndroidOS/SpamSold.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 30 72 64 7a 73 30 6c 64 69 65 72 7a 2e 63 6f 6d } //01 00  l0rdzs0ldierz.com
		$a_01_1 = {63 6f 6d 6d 61 6e 64 2e 70 68 70 3f 61 63 74 69 6f 6e 3d 73 65 6e 74 26 6e 75 6d 62 65 72 3d } //01 00  command.php?action=sent&number=
		$a_01_2 = {73 6d 73 6d 65 73 73 61 67 69 6e 67 2e 4d 61 69 6e } //00 00  smsmessaging.Main
	condition:
		any of ($a_*)
 
}