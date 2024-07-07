
rule Trojan_BAT_Sambetoc_A{
	meta:
		description = "Trojan:BAT/Sambetoc.A,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 6c 65 61 73 65 5c 61 75 74 6f 74 6f 75 63 68 2e 70 64 62 } //10 Release\autotouch.pdb
		$a_01_1 = {61 75 74 6f 73 6d 62 74 6f 75 63 68 } //10 autosmbtouch
		$a_01_2 = {67 65 74 5f 45 73 74 65 65 6d 61 75 64 69 74 74 6f 75 63 68 5f 78 6d 6c } //10 get_Esteemaudittouch_xml
		$a_01_3 = {67 65 74 5f 53 6d 62 74 6f 75 63 68 5f 78 6d 6c } //10 get_Smbtouch_xml
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}