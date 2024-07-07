
rule Trojan_BAT_Cymulate_MBCI_MTB{
	meta:
		description = "Trojan:BAT/Cymulate.MBCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {20 c8 00 00 00 28 90 01 01 00 00 0a 72 c4 57 00 70 28 90 01 01 00 00 0a 8e 2d e9 2b 0a 20 c8 00 00 00 28 90 01 01 00 00 0a 72 fe 57 00 70 28 90 01 01 00 00 0a 8e 2d e9 90 00 } //10
		$a_01_1 = {43 79 6d 75 6c 61 74 65 44 43 4f 4d 49 6e 74 65 72 66 61 63 65 73 57 6f 72 6d } //1 CymulateDCOMInterfacesWorm
		$a_01_2 = {43 79 6d 75 6c 61 74 65 45 44 52 52 61 6e 73 6f 6d } //1 CymulateEDRRansom
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}