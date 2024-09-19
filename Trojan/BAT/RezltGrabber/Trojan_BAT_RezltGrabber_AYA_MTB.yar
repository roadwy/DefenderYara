
rule Trojan_BAT_RezltGrabber_AYA_MTB{
	meta:
		description = "Trojan:BAT/RezltGrabber.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 00 6e 00 69 00 66 00 66 00 65 00 72 00 2e 00 7a 00 6f 00 70 00 7a 00 2d 00 61 00 70 00 69 00 2e 00 63 00 6f 00 6d 00 } //2 sniffer.zopz-api.com
		$a_00_1 = {61 00 75 00 74 00 68 00 2e 00 7a 00 6f 00 70 00 7a 00 2d 00 61 00 70 00 69 00 2e 00 63 00 6f 00 6d 00 } //2 auth.zopz-api.com
		$a_01_2 = {5a 4f 50 5a 2d 53 4e 49 46 46 2e 70 64 62 } //1 ZOPZ-SNIFF.pdb
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}