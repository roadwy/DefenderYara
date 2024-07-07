
rule Trojan_Win32_GootKit_A_MTB{
	meta:
		description = "Trojan:Win32/GootKit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 0b 02 83 c2 04 8d 40 f0 31 f0 83 e8 01 89 c6 50 8f 07 83 c7 04 83 eb 04 8d 05 90 01 04 05 90 01 04 50 c3 90 00 } //1
		$a_03_1 = {c7 05 54 cb 43 00 52 65 61 64 c7 05 90 01 04 50 72 6f 63 66 c7 05 90 01 04 65 73 66 c7 05 90 01 04 73 4d 68 90 01 04 a1 90 01 04 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}