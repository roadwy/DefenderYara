
rule Trojan_BAT_AllComeClipper_A_MTB{
	meta:
		description = "Trojan:BAT/AllComeClipper.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 00 4a 00 4b 00 4a 00 46 00 53 00 38 00 59 00 38 00 4d 00 2c 00 5a 00 46 00 } //1 KJKJFS8Y8M,ZF
		$a_01_1 = {49 00 4b 00 4a 00 4b 00 4a 00 46 00 53 00 38 00 59 00 38 00 4d 00 2c 00 5a 00 46 00 46 00 } //1 IKJKJFS8Y8M,ZFF
		$a_01_2 = {44 00 46 00 53 00 4b 00 4a 00 4b 00 4a 00 46 00 53 00 38 00 59 00 38 00 4d 00 2c 00 5a 00 46 00 41 00 57 00 57 00 52 00 } //1 DFSKJKJFS8Y8M,ZFAWWR
		$a_01_3 = {54 6f 49 6e 74 65 67 65 72 } //1 ToInteger
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}