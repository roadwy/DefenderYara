
rule Trojan_BAT_AsyncRat_NEH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58 0d 09 16 } //05 00 
		$a_01_1 = {28 17 00 00 0a 2b e6 28 05 00 00 06 2b e1 6f 18 00 00 0a 2b dc } //00 00 
	condition:
		any of ($a_*)
 
}