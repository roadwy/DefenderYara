
rule Trojan_Win32_StopCrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {81 6d d8 2f 62 16 14 81 45 e4 0f 07 b4 03 81 45 cc 93 b8 e8 1f 81 45 fc 58 6c e4 2f 81 45 c4 79 04 56 04 81 6d d4 26 88 9c 78 81 6d 98 98 5a a2 3b 81 45 b8 06 2f b1 78 81 45 cc 1c 73 a2 4a } //03 00 
		$a_01_1 = {81 fb 91 25 00 00 74 0f 43 81 fb ce 94 3f 05 0f 8c } //03 00 
		$a_01_2 = {81 ff 6e 27 87 01 7f 09 47 81 ff f6 ea 2b 33 7c a0 } //00 00 
	condition:
		any of ($a_*)
 
}