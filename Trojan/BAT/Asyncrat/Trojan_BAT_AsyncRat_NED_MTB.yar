
rule Trojan_BAT_AsyncRat_NED_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 16 11 06 6f 15 00 00 0a 11 04 6f 16 00 00 0a 09 11 05 16 20 a0 28 00 00 6f 17 00 00 0a 25 13 06 16 30 d9 } //5
		$a_01_1 = {7e 01 00 00 04 28 0d 00 00 06 28 07 00 00 0a 2a } //5
		$a_01_2 = {4d 41 49 4e 54 48 52 45 41 44 43 6c 41 53 53 } //5 MAINTHREADClASS
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}