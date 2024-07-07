
rule Trojan_Win32_Emotetcrypt_DR_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 01 0f b6 0a 03 c1 99 b9 c3 10 00 00 f7 f9 0f b6 04 2a 89 44 24 30 } //1
		$a_02_1 = {8b 4c 24 34 8b 44 24 20 0f be 04 08 50 ff 74 24 20 e8 90 01 04 59 59 8b 4c 24 34 ff 44 24 34 ff 4c 24 14 88 01 0f 85 90 00 } //1
		$a_81_2 = {50 63 79 47 49 53 30 56 4a 66 51 6f 48 34 6d 34 30 35 36 5a 38 75 74 69 42 73 48 75 36 36 4b 44 33 62 51 50 31 42 70 5a 48 36 4d 54 44 7a 34 4b 4f 6d 67 70 51 49 54 44 4f 54 57 74 68 51 51 54 } //1 PcyGIS0VJfQoH4m4056Z8utiBsHu66KD3bQP1BpZH6MTDz4KOmgpQITDOTWthQQT
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}