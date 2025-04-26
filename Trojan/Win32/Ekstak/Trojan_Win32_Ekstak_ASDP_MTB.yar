
rule Trojan_Win32_Ekstak_ASDP_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 b0 [0-04] 89 6e 00 00 be [0-04] 49 b9 fb 41 6e 00 00 dc 01 00 e1 } //5
		$a_01_1 = {2a 01 00 00 00 1b 08 72 00 92 6c 6e 00 00 be 0a 00 0b 33 49 b9 } //5
		$a_01_2 = {2a 01 00 00 00 74 c9 7a 00 eb 2d 77 00 00 be 0a 00 0b 33 49 b9 } //5
		$a_01_3 = {2a 01 00 00 00 13 55 78 00 8a b9 74 00 00 be 0a 00 0b 33 49 b9 63 72 74 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=5
 
}