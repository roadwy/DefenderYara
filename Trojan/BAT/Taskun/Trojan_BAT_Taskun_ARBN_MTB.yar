
rule Trojan_BAT_Taskun_ARBN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f 90 01 03 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 90 01 03 06 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a9 90 00 } //3
		$a_01_1 = {50 65 72 6d 69 73 73 69 6f 6e 56 69 65 77 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 PermissionViewer.Properties.Resources
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}