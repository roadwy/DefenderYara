
rule Trojan_BAT_Remcos_AGRT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AGRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 7e ?? ?? ?? 04 11 01 91 61 d2 6f } //2
		$a_01_1 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}