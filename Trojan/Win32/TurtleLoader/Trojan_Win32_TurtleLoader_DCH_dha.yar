
rule Trojan_Win32_TurtleLoader_DCH_dha{
	meta:
		description = "Trojan:Win32/TurtleLoader.DCH!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 64 61 74 61 2e 62 69 6e } //1 C:\Windows\data.bin
		$a_00_1 = {64 65 62 75 67 63 6f 6e 6e 65 63 74 77 69 64 65 } //1 debugconnectwide
		$a_01_2 = {7a 4c 41 78 75 55 30 6b 51 4b 66 33 73 57 45 37 65 50 52 4f 32 69 6d 79 67 39 47 53 70 56 6f 59 43 36 72 68 6c 58 34 38 5a 48 6e 76 6a 4a 44 42 4e 46 74 4d 64 31 49 35 61 63 77 62 71 54 2b 3d } //1 zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+=
		$a_03_3 = {80 e1 0f c1 e1 04 8a 5d 90 01 01 80 e3 3c 81 e3 ff 00 00 00 c1 eb 02 02 cb 90 00 } //1
		$a_03_4 = {80 e1 3f c1 e1 02 8a 5d 90 01 01 80 e3 30 81 e3 ff 00 00 00 c1 eb 04 02 cb 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}