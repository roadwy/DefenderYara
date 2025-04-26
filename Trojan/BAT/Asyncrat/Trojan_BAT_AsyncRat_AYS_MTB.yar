
rule Trojan_BAT_AsyncRat_AYS_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AYS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 2b 12 00 7e ?? 00 00 04 11 05 16 11 04 6f ?? ?? ?? 0a 00 00 09 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 25 13 04 16 fe 02 13 06 11 06 2d d5 } //2
		$a_01_1 = {31 00 35 00 39 00 2e 00 31 00 30 00 30 00 2e 00 31 00 33 00 2e 00 32 00 31 00 36 00 } //5 159.100.13.216
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*5) >=7
 
}