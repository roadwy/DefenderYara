
rule Trojan_MacOS_Padzer_B_MTB{
	meta:
		description = "Trojan:MacOS/Padzer.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 69 32 70 64 } //1 /tmp/i2pd
		$a_01_1 = {fe ff 74 2d 48 85 c9 75 14 48 8d 45 d8 48 8d 4d d7 48 89 4b 30 48 89 4b 28 48 89 43 38 44 88 31 48 8b 53 28 48 8b 4b 30 48 ff c1 48 89 4b 30 eb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}