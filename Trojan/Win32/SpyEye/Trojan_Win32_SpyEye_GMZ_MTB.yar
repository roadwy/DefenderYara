
rule Trojan_Win32_SpyEye_GMZ_MTB{
	meta:
		description = "Trojan:Win32/SpyEye.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 07 4e 03 ce 88 02 f7 d0 4e 03 c1 4b f7 d6 42 f7 d8 41 47 8b cf 41 0b db } //10
		$a_01_1 = {2e 63 79 6c 65 64 6e 68 } //1 .cylednh
		$a_01_2 = {2e 68 6d 6c 6d 72 65 69 } //1 .hmlmrei
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}