
rule Trojan_BAT_Stealer_AARP_MTB{
	meta:
		description = "Trojan:BAT/Stealer.AARP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 8e 69 8d ?? 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7 } //3
		$a_01_1 = {55 00 6d 00 56 00 6e 00 51 00 58 00 4e 00 74 00 4c 00 6d 00 56 00 34 00 5a 00 51 00 3d 00 3d 00 } //1 UmVnQXNtLmV4ZQ==
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}