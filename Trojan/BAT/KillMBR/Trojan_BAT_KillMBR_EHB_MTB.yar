
rule Trojan_BAT_KillMBR_EHB_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 6f 2a 00 00 0a 20 ff 00 00 00 5f d2 9c 00 07 17 58 0b 07 20 00 5e 01 00 fe 04 0c 08 2d dd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}