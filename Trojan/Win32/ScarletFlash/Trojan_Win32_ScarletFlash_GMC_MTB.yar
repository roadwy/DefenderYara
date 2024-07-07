
rule Trojan_Win32_ScarletFlash_GMC_MTB{
	meta:
		description = "Trojan:Win32/ScarletFlash.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 8b 5c 24 08 8a 03 8a 4c 24 0c d2 c0 32 c1 88 03 5b } //10
		$a_01_1 = {48 57 43 59 6c 45 5a 6e 44 59 6b 4e 6a } //1 HWCYlEZnDYkNj
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}