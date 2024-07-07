
rule Trojan_Win32_IcedID_C_MTB{
	meta:
		description = "Trojan:Win32/IcedID.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c f6 8b 1d 90 01 04 03 c9 8b c5 6b fe 0d f7 d8 c7 44 24 28 d8 f2 4b 00 2b c1 83 c4 0c 8b 0d 90 01 04 03 c8 b8 83 be a0 2f f7 e3 03 fb c1 ea 03 81 fa c5 e3 00 00 74 08 81 c3 11 df 93 22 eb 09 0f af d9 81 c3 c5 e3 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}