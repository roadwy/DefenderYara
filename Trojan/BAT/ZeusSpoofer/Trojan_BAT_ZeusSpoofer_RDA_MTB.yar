
rule Trojan_BAT_ZeusSpoofer_RDA_MTB{
	meta:
		description = "Trojan:BAT/ZeusSpoofer.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 65 75 73 53 70 6f 6f 66 65 72 42 61 73 65 } //1 ZeusSpooferBase
		$a_01_1 = {53 70 6f 6f 66 65 72 20 6d 65 6e 75 20 74 65 73 74 } //1 Spoofer menu test
		$a_01_2 = {4e 65 6d 65 73 69 73 2d 34 35 37 37 37 } //1 Nemesis-45777
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}