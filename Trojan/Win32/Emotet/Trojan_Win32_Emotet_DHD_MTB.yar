
rule Trojan_Win32_Emotet_DHD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {01 d8 8b 5c 24 14 81 c3 47 ae ff ff 66 89 d9 21 f8 66 89 4c 24 56 8b 7c 24 38 8a 04 07 8b 5c 24 1c 8b 54 24 0c 8a 24 13 c6 44 24 55 e8 30 e0 8b 54 24 18 8b 7c 24 0c 88 04 3a } //1
		$a_02_1 = {66 8b 44 24 78 66 b9 bd 61 66 29 c1 8b 54 24 38 66 89 0a 8b 54 24 2c 81 f2 48 61 4b 6b [0-16] c7 42 3c 38 01 00 00 8b 54 24 38 66 8b 44 24 1a 66 0d aa 22 66 89 44 24 76 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}