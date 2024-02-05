
rule Trojan_Win32_CryptInject_DO_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 45 b8 bd 15 07 42 81 6d 98 e6 13 c0 4a 81 45 d8 9c c4 21 1f 81 45 a0 43 58 2a 1c 8b 45 fc 33 c2 33 c1 81 3d 90 02 04 a3 01 00 00 89 45 fc 75 20 90 00 } //01 00 
		$a_01_1 = {3d 60 4b da 26 7f 0c 40 3d b6 ad 81 5b 0f 8c } //00 00 
	condition:
		any of ($a_*)
 
}