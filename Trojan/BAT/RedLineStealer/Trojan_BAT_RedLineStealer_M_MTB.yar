
rule Trojan_BAT_RedLineStealer_M_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 ff a2 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 cb 00 00 00 88 00 00 00 2c 01 00 00 64 02 } //2
		$a_01_1 = {6f 73 5f 63 72 79 70 74 } //1 os_crypt
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 5f 6b 65 79 } //1 encrypted_key
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}