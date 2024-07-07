
rule Trojan_Win32_Lethic_R_bit{
	meta:
		description = "Trojan:Win32/Lethic.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //1 svchost.exe -k netsvcs
		$a_03_1 = {0f b6 03 8b c8 c1 e9 04 83 f9 0a 7d 05 80 c1 90 01 01 eb 03 80 c1 90 01 01 83 e0 0f 88 8a 90 01 04 83 f8 0a 7d 04 04 90 01 01 eb 02 04 90 01 01 88 82 90 01 04 6a 10 83 c2 02 58 4b 3b d0 72 90 00 } //1
		$a_03_2 = {8b c1 c1 e0 19 33 c1 c1 e0 02 33 c1 c1 e0 02 33 c1 03 c0 33 c1 03 c0 33 c1 25 90 01 04 d1 e9 0b c1 a3 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}