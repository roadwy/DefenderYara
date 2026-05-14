
rule Trojan_Win32_AntiAV_GPAK_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.GPAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 b8 da 49 00 95 71 3a 00 00 58 35 00 cc 61 6d 4a 85 45 3a } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}