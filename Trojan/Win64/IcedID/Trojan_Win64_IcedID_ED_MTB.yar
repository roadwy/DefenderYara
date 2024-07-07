
rule Trojan_Win64_IcedID_ED_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 c1 f8 1f 01 ca c1 fa 04 29 c2 89 c8 0f af d5 29 d0 48 63 d0 41 0f b6 14 10 41 32 14 0b 41 88 14 09 } //8
	condition:
		((#a_01_0  & 1)*8) >=8
 
}
rule Trojan_Win64_IcedID_ED_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {79 61 72 65 74 64 6a 62 6b 61 73 76 64 61 6a 61 73 64 } //10 yaretdjbkasvdajasd
		$a_01_1 = {10 00 00 00 00 00 80 01 00 00 00 00 10 00 00 00 02 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}