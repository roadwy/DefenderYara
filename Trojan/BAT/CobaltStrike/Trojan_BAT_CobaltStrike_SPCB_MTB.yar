
rule Trojan_BAT_CobaltStrike_SPCB_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrike.SPCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 07 06 5d 6f ?? 00 00 0a d2 61 d2 52 00 07 17 58 0b 07 02 50 8e 69 fe 04 0c 08 2d d8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}