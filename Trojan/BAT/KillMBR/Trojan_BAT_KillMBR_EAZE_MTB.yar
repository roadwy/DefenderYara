
rule Trojan_BAT_KillMBR_EAZE_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.EAZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 6f 0a 00 00 0a 20 ff 00 00 00 5f d2 9c 07 17 58 0b 07 20 aa ae 01 00 32 e3 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}