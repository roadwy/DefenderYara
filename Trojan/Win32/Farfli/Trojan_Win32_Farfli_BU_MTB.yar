
rule Trojan_Win32_Farfli_BU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 14 01 80 f2 20 80 c2 7b 88 14 01 41 3b ce 7c } //4
		$a_01_1 = {50 6c 75 67 69 6e 4d 65 } //1 PluginMe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}