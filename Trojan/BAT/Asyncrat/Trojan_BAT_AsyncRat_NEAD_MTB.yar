
rule Trojan_BAT_AsyncRat_NEAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 01 2a 02 28 17 00 00 0a 28 14 00 00 06 28 18 00 00 0a 73 19 00 00 0a 13 00 } //5
		$a_01_1 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //2 cdn.discordapp.com
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}