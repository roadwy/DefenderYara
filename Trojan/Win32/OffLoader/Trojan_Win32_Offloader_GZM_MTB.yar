
rule Trojan_Win32_Offloader_GZM_MTB{
	meta:
		description = "Trojan:Win32/Offloader.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 72 61 73 73 66 6f 72 63 65 2e 73 69 74 65 2f 70 6c 6f 73 73 2e 70 68 70 } //2 https://brassforce.site/ploss.php
		$a_01_1 = {67 6f 6f 2e 67 6c 2f 66 78 54 69 4b 5a } //2 goo.gl/fxTiKZ
		$a_01_2 = {6f 6e 6c 79 2f 70 70 62 61 } //1 only/ppba
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 73 64 66 77 73 64 66 73 36 64 66 } //1 Software\sdfwsdfs6df
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}