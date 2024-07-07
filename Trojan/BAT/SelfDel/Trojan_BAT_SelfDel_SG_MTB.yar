
rule Trojan_BAT_SelfDel_SG_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 64 73 62 63 2e 65 78 65 } //1 adsbc.exe
		$a_01_1 = {67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 } //1 get_ExecutablePath
		$a_01_2 = {61 64 73 62 63 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 adsbc.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}