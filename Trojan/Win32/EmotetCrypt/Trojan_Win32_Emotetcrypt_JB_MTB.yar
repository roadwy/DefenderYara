
rule Trojan_Win32_Emotetcrypt_JB_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 0c 00 2b d9 0f af d8 b8 01 00 00 00 03 d3 2b c5 0f af 05 90 01 04 8d 4c 00 05 8b 44 24 30 0f af 0d 90 01 04 0f af 05 90 01 04 03 ce 03 ca 8a 0c 08 8b 44 24 2c 8a 18 32 d9 88 18 90 00 } //01 00 
		$a_01_1 = {73 5f 29 78 37 23 34 56 46 2b 55 72 5f 6b 63 25 72 58 5e 72 36 23 6f 55 2a 28 40 71 23 3f 36 2a 5a 36 52 39 5f 6c 5a 54 33 62 54 5a 76 38 57 39 2a 46 55 3f 5a 4f 53 36 66 77 5e 69 5e 31 51 4a 4c 47 77 35 36 75 } //00 00  s_)x7#4VF+Ur_kc%rX^r6#oU*(@q#?6*Z6R9_lZT3bTZv8W9*FU?ZOS6fw^i^1QJLGw56u
	condition:
		any of ($a_*)
 
}