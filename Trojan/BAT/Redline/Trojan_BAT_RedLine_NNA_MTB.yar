
rule Trojan_BAT_RedLine_NNA_MTB{
	meta:
		description = "Trojan:BAT/RedLine.NNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 65 66 20 41 01 00 00 28 dd 07 00 06 61 2a } //2
		$a_81_1 = {66 34 61 36 63 31 38 37 2d 61 38 36 33 2d 34 38 38 63 2d 38 34 37 33 2d 64 39 37 31 31 33 34 35 61 39 37 39 } //1 f4a6c187-a863-488c-8473-d9711345a979
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}