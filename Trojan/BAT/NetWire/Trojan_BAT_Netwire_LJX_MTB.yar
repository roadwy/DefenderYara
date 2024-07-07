
rule Trojan_BAT_Netwire_LJX_MTB{
	meta:
		description = "Trojan:BAT/Netwire.LJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 8d 5e 00 00 01 25 16 1f 23 9d 28 90 01 03 0a 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 28 90 01 03 0a 74 48 00 00 01 0a 2b 00 06 2a 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}