
rule Trojan_BAT_RedLine_EAP_MTB{
	meta:
		description = "Trojan:BAT/RedLine.EAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8e 69 fe 04 fe 90 01 01 06 00 20 50 00 00 00 fe 90 01 01 08 00 00 fe 90 01 01 08 00 20 04 00 00 00 fe 01 39 90 01 01 00 00 00 fe 09 00 00 73 90 01 01 00 00 0a 7d 90 01 01 00 00 04 20 05 00 00 00 fe 90 01 01 08 00 00 fe 90 01 01 08 00 20 4d 00 00 00 fe 01 39 90 01 01 00 00 00 fe 0c 02 00 fe 0c 05 00 fe 0c 01 00 fe 0c 05 00 9a 20 10 00 00 00 28 90 01 01 00 00 0a d2 9c 20 90 00 } //3
		$a_01_1 = {57 69 6e 43 6f 6e 74 72 6f 6c 73 2e 50 44 4f 43 6f 6e 74 72 6f 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //2 WinControls.PDOControls.resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}