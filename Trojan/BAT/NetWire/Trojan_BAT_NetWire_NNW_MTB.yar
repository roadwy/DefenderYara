
rule Trojan_BAT_NetWire_NNW_MTB{
	meta:
		description = "Trojan:BAT/NetWire.NNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 00 8e 69 5d 91 7e ?? 00 00 04 11 03 91 61 d2 6f ?? 00 00 0a } //5
		$a_01_1 = {46 00 6c 00 6a 00 65 00 7a 00 65 00 75 00 } //1 Fljezeu
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}