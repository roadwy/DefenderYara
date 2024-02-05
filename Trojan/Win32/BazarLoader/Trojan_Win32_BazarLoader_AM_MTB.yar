
rule Trojan_Win32_BazarLoader_AM_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {50 53 81 ec 80 05 00 00 a1 90 01 04 33 c5 89 45 ec 56 57 50 8d 45 f4 64 a3 90 01 04 8b 73 10 8d 85 08 fb ff ff 90 00 } //0a 00 
		$a_00_1 = {0f be c0 8d 76 01 83 e8 30 0f af c1 8d 0c 49 c1 e1 02 03 d0 8a 06 84 c0 75 e6 81 f2 00 10 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}