
rule Trojan_Win32_RMSRat_A_MTB{
	meta:
		description = "Trojan:Win32/RMSRat.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c3 0f b6 ca 0f af c8 8a 44 24 90 01 01 02 0c 2b 32 c1 43 88 44 24 90 01 01 88 04 32 83 fb 90 00 } //2
		$a_03_1 = {0f b6 c9 0f b6 c3 0f af c8 8b 44 24 90 01 01 02 0c 28 32 d1 8b c8 41 88 14 33 89 4c 24 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}