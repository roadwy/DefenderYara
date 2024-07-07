
rule Trojan_Win32_Ruandmel_A_bit{
	meta:
		description = "Trojan:Win32/Ruandmel.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 04 8d 04 40 8b 0c 85 90 01 04 8b 44 24 08 8b 44 c1 04 8b 0c 24 83 c4 08 89 0c 24 ff e0 90 00 } //1
		$a_03_1 = {2b c7 89 45 0c 8a 04 38 88 45 13 8b 01 40 25 ff 00 00 00 8d 34 01 89 01 0f b6 46 08 03 41 04 25 ff 00 00 00 89 41 04 8a 56 08 0f b6 44 08 08 88 46 08 8b 41 04 88 54 08 08 85 ff 74 90 01 01 8b 41 04 0f b6 54 08 08 8b 01 0f b6 44 08 08 03 d0 81 e2 ff 00 00 80 79 90 01 01 4a 81 ca 00 ff ff ff 42 8a 54 0a 08 32 55 13 88 17 8b 45 0c 47 4b 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}