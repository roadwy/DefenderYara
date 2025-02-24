
rule Trojan_AndroidOS_Nandrobox_A{
	meta:
		description = "Trojan:AndroidOS/Nandrobox.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 6f 62 69 6c 65 68 6f 74 64 6f 67 2e 63 6f 6d 2f 63 6e 78 6d 6c 72 70 63 2f 78 6d 6c 2e 70 68 70 } //2 mobilehotdog.com/cnxmlrpc/xml.php
		$a_01_1 = {53 54 52 49 4e 47 5f 53 55 43 57 4f 52 44 } //2 STRING_SUCWORD
		$a_01_2 = {53 54 52 49 4e 47 5f 46 45 45 43 55 45 } //2 STRING_FEECUE
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}