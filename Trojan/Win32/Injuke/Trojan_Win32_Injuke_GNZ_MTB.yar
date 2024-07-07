
rule Trojan_Win32_Injuke_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {0c bb 31 30 33 66 b8 87 0b 89 44 24 0d 8d 34 b5 90 01 04 8f 44 24 09 b9 90 01 04 66 ff 74 24 08 90 00 } //10
		$a_01_1 = {20 53 68 69 65 6c 64 65 6e 20 76 32 2e 34 2e 30 2e 30 00 eb } //10
		$a_01_2 = {44 43 6b 68 6d 45 } //1 DCkhmE
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}