
rule Trojan_Win32_Phave_KK_MTB{
	meta:
		description = "Trojan:Win32/Phave.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 40 00 c7 45 ?? 00 00 00 00 c7 44 24 18 00 00 00 00 c7 44 24 14 00 00 00 00 8d 45 ?? 89 44 24 10 c7 44 24 0c 00 00 00 00 c7 44 24 08 01 00 00 00 c7 44 24 04 00 00 00 00 8b 45 ?? 89 04 24 8b 45 dc } //10
		$a_01_1 = {8b 45 f4 3b 45 0c 73 33 8b 55 08 8b 45 f4 8d 0c 02 8b 55 08 8b 45 f4 01 d0 0f b6 00 89 c3 8b 45 f4 ba 00 00 00 00 f7 75 f0 8b 45 10 01 d0 0f b6 00 31 d8 88 01 83 45 f4 01 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}