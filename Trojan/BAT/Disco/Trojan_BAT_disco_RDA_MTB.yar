
rule Trojan_BAT_disco_RDA_MTB{
	meta:
		description = "Trojan:BAT/disco.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 62 66 63 38 30 38 64 2d 63 31 62 36 2d 34 36 30 35 2d 39 66 31 30 2d 31 30 61 64 33 31 38 34 37 30 62 65 } //1 cbfc808d-c1b6-4605-9f10-10ad318470be
		$a_01_1 = {4e 65 74 54 72 61 63 6b } //1 NetTrack
		$a_01_2 = {53 79 73 74 65 6d 49 6e 66 6f 41 70 70 } //1 SystemInfoApp
		$a_01_3 = {49 73 55 73 65 72 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 IsUserAdministrator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}