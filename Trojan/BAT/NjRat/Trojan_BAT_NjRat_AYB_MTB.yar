
rule Trojan_BAT_NjRat_AYB_MTB{
	meta:
		description = "Trojan:BAT/NjRat.AYB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 54 4f 43 48 4f 4c 4d 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 53 54 4f 43 48 4f 4c 4d 2e 70 64 62 } //5 STOCHOLM\obj\x86\Release\STOCHOLM.pdb
		$a_01_1 = {53 54 4f 43 48 4f 4c 4d 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //2 STOCHOLM.Form1.resources
		$a_01_2 = {24 35 37 33 61 63 36 34 39 2d 62 63 30 38 2d 34 35 33 31 2d 38 65 39 35 2d 65 31 33 61 64 61 30 35 36 30 31 31 } //2 $573ac649-bc08-4531-8e95-e13ada056011
		$a_01_3 = {53 54 4f 43 48 4f 4c 4d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 STOCHOLM.Properties.Resources
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=10
 
}