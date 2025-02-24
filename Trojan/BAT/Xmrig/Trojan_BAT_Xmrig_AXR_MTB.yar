
rule Trojan_BAT_Xmrig_AXR_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.AXR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 47 11 00 11 01 11 00 8e 69 5d 91 11 01 1f 63 58 11 00 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 } //2
		$a_01_1 = {70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 39 00 39 00 } //1 password99
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}