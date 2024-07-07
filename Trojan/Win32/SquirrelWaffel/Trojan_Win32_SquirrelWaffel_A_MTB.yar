
rule Trojan_Win32_SquirrelWaffel_A_MTB{
	meta:
		description = "Trojan:Win32/SquirrelWaffel.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf 6b c9 33 2b ca 2b ca 8d 5c 39 90 01 01 2a c2 b1 53 f6 e9 8a ca 02 c9 02 c1 02 c3 2c 01 b1 53 f6 e9 8a ca 2a c8 90 00 } //1
		$a_03_1 = {0f b6 c8 6b c9 53 56 8b 35 90 01 04 2b f1 8d 4c 32 90 01 01 66 0f b6 d0 66 03 d6 66 83 ea 5c 0f b7 d2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}