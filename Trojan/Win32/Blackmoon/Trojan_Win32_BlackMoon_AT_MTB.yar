
rule Trojan_Win32_BlackMoon_AT_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {26 67 88 58 9b 06 45 1e aa 7e 40 7c 51 3b a4 c2 9e 0a c6 4c 13 06 5b 35 70 2d 48 50 00 20 ed 6d 0c 3f 2e db df dc 75 ac 95 ad b1 98 24 19 44 ?? 24 b9 33 14 99 ea 13 71 5a 5b 46 da 5a a2 c7 73 01 40 c6 05 3c 25 8b 07 a8 76 ca fe 26 0e 81 aa a2 37 22 00 8a f7 fe 47 2f 05 e9 61 af ef b8 7b b6 f6 b8 4e 6e e5 f2 a7 ff 08 00 80 d4 d9 12 d1 ba 5a 1e 8e 1d 05 45 89 cb 0e 8a c2 07 c1 e0 28 15 2a 80 4a 8b c8 79 fc b4 7f 30 78 bc 3f 09 2b 00 18 } //1
		$a_00_1 = {80 fe 3d 66 0f ab f9 f9 89 f9 66 0f bb fe 48 ff ce c1 d6 02 f8 29 d9 66 0f bc f6 48 89 e6 f5 85 d7 f9 48 81 fd a8 a7 5b 69 48 83 ef 08 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}