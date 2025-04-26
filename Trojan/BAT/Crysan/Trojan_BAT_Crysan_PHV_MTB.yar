
rule Trojan_BAT_Crysan_PHV_MTB{
	meta:
		description = "Trojan:BAT/Crysan.PHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 08 20 b7 5c 8a 00 6a 5e 6d 13 07 16 13 0b 2b 2b 11 05 11 0b 8f ?? 00 00 01 25 47 08 d2 61 d2 52 11 0b 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0b 17 58 13 0b 11 0b 11 05 8e 69 32 cd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}