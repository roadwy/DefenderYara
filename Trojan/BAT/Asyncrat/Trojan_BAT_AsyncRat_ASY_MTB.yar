
rule Trojan_BAT_AsyncRat_ASY_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 26 26 28 ?? ?? ?? 06 25 26 02 20 60 01 00 00 28 ?? ?? ?? 06 02 8e 69 28 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_2{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 16 0c 2b 0f 02 7b 58 00 00 0a 08 07 08 91 9c 08 17 58 0c 08 19 32 ed de 0a 06 2c 06 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_3{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 13 00 00 01 0a 06 72 41 00 00 70 6f ?? 00 00 0a 00 72 49 00 00 70 0b 06 6f ?? 00 00 0a 74 14 00 00 01 0c 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_4{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 2d 06 08 6f ?? ?? ?? 0a 03 08 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0d 07 09 28 ?? ?? ?? 0a 8c 3e 00 00 01 28 ?? ?? ?? 0a 0b 08 17 58 0c 08 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AsyncRat_ASY_MTB_5{
	meta:
		description = "Trojan:BAT/AsyncRat.ASY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 0d 16 13 04 2b 36 11 04 1f 30 5d 16 fe 01 13 05 11 05 2c 15 08 07 11 04 91 20 ff 00 00 00 61 b4 6f ?? 00 00 0a 00 00 2b 0d 00 08 07 11 04 91 6f ?? 00 00 0a 00 00 11 04 17 d6 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}