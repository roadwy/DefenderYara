
rule Trojan_Win32_Zbot_AMAD_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 78 79 2d 43 6f 6e 6e 65 63 74 69 6f 6e } //1 Proxy-Connection
		$a_01_1 = {3d 2d 3d 2d 50 61 4e 64 41 21 24 32 } //1 =-=-PaNdA!$2
		$a_01_2 = {2d 21 2d 40 68 6a 30 31 4e 2e 2f 31 } //1 -!-@hj01N./1
		$a_03_3 = {8d 3c 01 8a c8 02 c9 b2 f6 2a d1 00 17 eb ?? 8a d0 02 d2 03 c8 80 c2 07 00 11 40 3b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}