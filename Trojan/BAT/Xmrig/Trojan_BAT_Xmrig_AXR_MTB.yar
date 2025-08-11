
rule Trojan_BAT_Xmrig_AXR_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 47 11 00 11 01 11 00 8e 69 5d 91 11 01 1f 63 58 11 00 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 } //2
		$a_01_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 39 00 39 00 } //1 password99
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Xmrig_AXR_MTB_2{
	meta:
		description = "Trojan:BAT/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 5b 00 00 70 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 05 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 07 00 00 0a 13 04 11 04 7e 01 00 00 04 16 7e 01 00 00 04 8e 69 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}