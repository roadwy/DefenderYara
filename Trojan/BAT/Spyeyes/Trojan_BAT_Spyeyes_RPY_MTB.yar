
rule Trojan_BAT_Spyeyes_RPY_MTB{
	meta:
		description = "Trojan:BAT/Spyeyes.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 07 6f 11 00 00 0a 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 28 09 00 00 0a 6f 14 00 00 0a 26 07 17 58 0b 07 02 6f 12 00 00 0a 32 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}