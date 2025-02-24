
rule Trojan_Win32_DllHijack_A_MTB{
	meta:
		description = "Trojan:Win32/DllHijack.A!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 c7 c6 44 24 3c 74 81 3f 50 45 00 00 0f b7 47 14 89 7c 24 24 89 54 24 38 0f 85 27 ff ff ff 0f b7 7f 06 89 7c 24 20 66 85 ff 0f 84 16 ff ff ff 8b 7c 24 24 89 4c 24 2c 8d 6c 24 38 8d 74 07 18 31 ff 8d b4 26 00 00 00 00 66 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}