
rule Trojan_BAT_Xmrig_NEB_MTB{
	meta:
		description = "Trojan:BAT/Xmrig.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 03 00 00 04 06 7e 03 00 00 04 06 91 06 61 00 23 00 00 00 00 00 00 00 40 23 00 00 00 00 00 40 55 40 5a 28 19 00 00 0a 61 d2 9c 06 17 58 0a 06 7e 03 00 00 04 8e 69 fe 04 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}