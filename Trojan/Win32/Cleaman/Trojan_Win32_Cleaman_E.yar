
rule Trojan_Win32_Cleaman_E{
	meta:
		description = "Trojan:Win32/Cleaman.E,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 85 2c fd ff ff 90 01 04 8b 45 ec c6 40 01 65 8b 4d ec c6 41 08 65 90 00 } //1
		$a_01_1 = {c6 45 fa 00 8b 45 ec c6 40 01 65 8b 4d ec c6 41 04 70 8d 55 f4 52 ff 15 } //1
		$a_03_2 = {0f b7 04 4a c1 f8 0c 83 f8 03 75 90 01 01 c7 85 78 ff ff ff 90 01 02 00 00 8b 4d 8c 8b 95 7c ff ff ff 0f b7 04 4a 50 e8 90 00 } //1
		$a_00_3 = {5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 33 00 72 00 35 00 77 00 65 00 72 00 67 00 2e 00 74 00 78 00 74 00 } //1 \drivers\3r5werg.txt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}