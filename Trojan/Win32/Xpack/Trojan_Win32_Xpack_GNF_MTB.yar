
rule Trojan_Win32_Xpack_GNF_MTB{
	meta:
		description = "Trojan:Win32/Xpack.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b c6 53 8b f1 66 83 fa 10 90 01 02 33 d2 8a 18 8b ca 81 e1 90 01 04 8a 4c 4c 0c 32 d9 42 88 18 40 4e 90 00 } //01 00 
		$a_01_1 = {62 73 33 36 30 2e 63 6f 2e 63 63 } //00 00  bs360.co.cc
	condition:
		any of ($a_*)
 
}