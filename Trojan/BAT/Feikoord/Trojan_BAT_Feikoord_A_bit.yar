
rule Trojan_BAT_Feikoord_A_bit{
	meta:
		description = "Trojan:BAT/Feikoord.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 02 00 00 04 06 7e 02 00 00 04 06 91 7e 01 00 00 04 06 7e 01 00 00 04 28 04 00 00 06 5d 91 61 28 16 00 00 0a 9c 06 17 58 0a 06 7e 02 00 00 04 28 04 00 00 06 32 c9 } //1
		$a_03_1 = {0a 16 0b 2b 25 06 28 17 00 00 06 72 90 01 04 07 8c 39 00 00 01 28 52 00 00 0a 6f 53 00 00 0a 28 54 00 00 0a 0a 07 17 58 0b 07 28 1b 00 00 06 32 d3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}