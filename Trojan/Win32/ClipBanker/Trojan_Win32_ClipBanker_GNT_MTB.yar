
rule Trojan_Win32_ClipBanker_GNT_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GNT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {38 39 2e 31 31 39 2e 36 37 2e 31 35 34 2f } //2 89.119.67.154/
		$a_01_1 = {6b 75 6b 75 74 72 75 73 74 6e 65 74 37 37 37 2e 69 6e 66 6f } //2 kukutrustnet777.info
		$a_01_2 = {4d 5a 74 69 42 79 47 57 69 } //1 MZtiByGWi
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}