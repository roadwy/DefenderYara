
rule Trojan_Win32_Ekstak_CI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 14 2e 5e 33 c3 33 c2 3d 4e e6 40 bb 74 90 01 01 f7 05 90 01 04 00 00 ff ff 0f 85 90 01 04 b8 2b 25 cd b5 eb 90 00 } //1
		$a_02_1 = {31 c8 59 89 3c 28 58 5f 3d 4e e6 40 bb 0f 84 90 01 04 a9 00 00 ff ff e9 90 01 04 eb 90 01 01 81 c2 73 54 c4 ea 31 d6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}