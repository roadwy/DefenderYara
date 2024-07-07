
rule Trojan_BAT_NjRat_NEBH_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_01_0 = {0b 07 14 fe 01 16 fe 01 0d 09 39 14 00 00 00 02 03 04 07 28 30 00 00 06 0a 38 34 00 00 00 38 26 00 00 00 00 05 75 35 00 00 01 0c 08 14 fe 01 16 fe 01 0d 09 } //10
		$a_01_1 = {54 00 68 00 69 00 73 00 20 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 20 00 69 00 73 00 20 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 } //2 This assembly is protected
		$a_01_2 = {49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 4c 00 6f 00 63 00 6b 00 } //2 IntelliLock
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}