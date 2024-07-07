
rule Trojan_Win32_Kovter_S{
	meta:
		description = "Trojan:Win32/Kovter.S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b 72 28 6a 18 59 31 ff 31 c0 ac 3c 61 7c 02 2c 20 c1 cf 0d 01 c7 e2 f0 81 ff 90 01 04 8b 5a 10 8b 12 75 db 90 00 } //1
		$a_01_1 = {8b 45 fc 89 45 d4 8b 45 d4 66 81 38 4d 5a 0f 85 0f 02 00 00 8b 45 fc 33 d2 52 50 8b 45 d4 8b 40 3c 99 03 04 24 13 54 24 04 83 c4 08 89 45 d0 8b 45 d0 81 38 50 45 00 00 0f 85 e5 01 00 00 } //1
		$a_01_2 = {c6 85 2f ff ff ff 61 c6 85 30 ff ff ff 64 c6 85 31 ff ff ff 76 c6 85 32 ff ff ff 61 c6 85 33 ff ff ff 70 c6 85 34 ff ff ff 69 c6 85 35 ff ff ff 33 c6 85 36 ff ff ff 32 c6 85 37 ff ff ff 2e c6 85 38 ff ff ff 64 c6 85 39 ff ff ff 6c c6 85 3a ff ff ff 6c c6 85 3b ff ff ff 00 } //1
		$a_03_3 = {03 cb 81 39 52 65 67 4f 75 90 01 01 8d 41 04 81 38 70 65 6e 4b 75 50 90 00 } //1
		$a_01_4 = {81 39 45 78 69 74 75 } //1
		$a_01_5 = {81 38 50 72 6f 63 75 } //1
		$a_00_6 = {73 00 68 00 65 00 6c 00 6c 00 3c 00 3c 00 3a 00 3a 00 3e 00 3e 00 } //1 shell<<::>>
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}