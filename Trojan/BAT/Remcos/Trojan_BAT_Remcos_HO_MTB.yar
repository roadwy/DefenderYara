
rule Trojan_BAT_Remcos_HO_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 05 04 5d 91 03 05 1f 16 5d 6f ?? ?? ?? 0a 61 0a [0-02] 06 2a } //1
		$a_03_1 = {20 00 01 00 00 0a 03 02 20 00 7a 00 00 04 28 ?? ?? ?? 06 03 04 17 58 20 00 7a 00 00 5d 91 59 06 58 06 5d 0b 03 04 20 00 7a 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}