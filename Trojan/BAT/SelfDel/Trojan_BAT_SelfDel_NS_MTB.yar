
rule Trojan_BAT_SelfDel_NS_MTB{
	meta:
		description = "Trojan:BAT/SelfDel.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 72 59 18 00 70 7d 06 00 00 04 02 28 ?? 00 00 0a 0a 12 00 fe ?? ?? 00 00 01 6f ?? 00 00 0a 7d 07 00 00 04 02 72 09 18 00 70 d0 03 00 00 02 28 ?? 00 00 0a 6f ?? 00 00 0a 73 1b 00 00 0a } //2
		$a_01_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /f /im
		$a_01_2 = {6e 00 65 00 77 00 46 00 72 00 6f 00 6e 00 74 00 54 00 6f 00 6f 00 6c 00 73 00 2e 00 65 00 78 00 65 00 } //1 newFrontTools.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}