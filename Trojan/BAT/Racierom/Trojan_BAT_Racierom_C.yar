
rule Trojan_BAT_Racierom_C{
	meta:
		description = "Trojan:BAT/Racierom.C,SIGNATURE_TYPE_PEHSTR_EXT,68 01 54 01 07 00 00 "
		
	strings :
		$a_01_0 = {61 72 69 65 63 2e 61 72 69 61 70 61 6c 61 63 68 2e 72 65 73 6f 75 72 63 65 73 } //200 ariec.ariapalach.resources
		$a_01_1 = {00 67 65 61 72 74 69 65 2e 65 78 65 00 } //100
		$a_01_2 = {73 00 76 00 6e 00 68 00 6f 00 73 00 74 00 } //20 svnhost
		$a_01_3 = {2f 00 66 00 20 00 2f 00 69 00 6d 00 20 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //20 /f /im explorer.exe
		$a_01_4 = {73 65 6c 61 76 69 00 73 65 6c 6c 00 73 65 74 5f 41 } //20
		$a_01_5 = {73 61 6c 65 72 65 72 00 73 63 63 72 61 70 6b 69 73 } //20
		$a_01_6 = {65 65 66 33 65 00 65 67 73 77 } //20 敥㍦e来睳
	condition:
		((#a_01_0  & 1)*200+(#a_01_1  & 1)*100+(#a_01_2  & 1)*20+(#a_01_3  & 1)*20+(#a_01_4  & 1)*20+(#a_01_5  & 1)*20+(#a_01_6  & 1)*20) >=340
 
}