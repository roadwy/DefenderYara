
rule Trojan_BAT_RemcosRAT_NEE_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 14 00 00 0a 28 90 01 03 06 6f 90 01 03 0a 28 90 01 03 06 28 90 01 03 06 13 00 38 90 01 03 00 dd 90 01 03 ff 26 38 90 01 03 00 dd 90 01 03 ff 90 00 } //5
		$a_01_1 = {4e 6a 73 77 70 73 67 } //1 Njswpsg
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}