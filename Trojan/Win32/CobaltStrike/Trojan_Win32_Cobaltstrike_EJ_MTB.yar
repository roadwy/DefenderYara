
rule Trojan_Win32_Cobaltstrike_EJ_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 f7 eb c1 fa 90 01 01 41 89 d2 44 89 c0 c1 f8 90 01 01 41 29 c2 44 89 d0 c1 e0 90 01 01 42 8d 04 50 44 89 c2 29 c2 48 63 d2 48 8b 0d 90 01 04 0f b6 14 11 42 32 94 04 90 01 04 43 88 14 01 90 00 } //1
		$a_03_1 = {41 f7 ea c1 fa 90 01 01 89 c8 c1 f8 90 01 01 29 c2 89 d0 c1 e0 90 01 01 8d 14 50 41 29 d1 4d 63 c9 48 8b 05 90 01 04 42 0f b6 04 08 32 44 0c 90 01 01 41 88 04 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}