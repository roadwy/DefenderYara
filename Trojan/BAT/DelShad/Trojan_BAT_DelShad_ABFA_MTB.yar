
rule Trojan_BAT_DelShad_ABFA_MTB{
	meta:
		description = "Trojan:BAT/DelShad.ABFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 1a 58 4a 02 8e 69 5d 7e ?? 00 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? 00 06 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}