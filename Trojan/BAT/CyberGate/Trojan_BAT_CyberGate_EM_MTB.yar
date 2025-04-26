
rule Trojan_BAT_CyberGate_EM_MTB{
	meta:
		description = "Trojan:BAT/CyberGate.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d6 20 00 01 00 00 5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 03 50 11 0a 03 50 11 0a 91 11 05 08 91 61 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}