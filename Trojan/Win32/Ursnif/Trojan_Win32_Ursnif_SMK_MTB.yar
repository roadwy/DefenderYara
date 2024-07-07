
rule Trojan_Win32_Ursnif_SMK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.SMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6c 24 20 2f 8b d7 6b d2 2f 8b d9 2b da b2 26 f6 ea 66 03 f3 8a d8 2a 5c 24 14 66 89 35 90 01 04 88 1d 90 01 04 8b c5 6b c0 03 83 e8 08 81 7c 24 10 87 00 00 00 99 a3 90 01 04 89 15 90 01 04 77 40 66 0f b6 cb 8d 04 3f 66 03 c1 66 03 c6 b9 fb 79 00 00 66 2b c1 90 02 20 b1 26 f6 e9 8b 0d 90 01 04 2a c3 8a d8 88 1d 90 01 04 a1 90 01 04 6b c0 26 2b 44 24 1c 0f b7 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}