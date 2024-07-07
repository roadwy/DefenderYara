
rule Trojan_BAT_NanoCore_NEA_MTB{
	meta:
		description = "Trojan:BAT/NanoCore.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 64 64 39 30 66 31 63 37 2d 66 31 66 38 2d 34 65 62 34 2d 61 39 66 36 2d 62 39 66 38 39 30 64 32 65 30 38 66 } //1 $dd90f1c7-f1f8-4eb4-a9f6-b9f890d2e08f
		$a_01_1 = {73 77 78 62 65 6e 2e 57 69 6e 64 6f 77 73 } //1 swxben.Windows
		$a_01_2 = {45 4d 5f 53 45 54 43 55 45 42 41 4e 4e 45 52 } //1 EM_SETCUEBANNER
		$a_01_3 = {43 43 20 42 59 2d 53 41 20 33 2e 30 } //1 CC BY-SA 3.0
		$a_01_4 = {51 41 44 47 57 47 47 } //1 QADGWGG
		$a_01_5 = {45 43 4d 5f 46 49 52 53 54 } //1 ECM_FIRST
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}