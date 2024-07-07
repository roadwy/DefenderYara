
rule PWS_Win32_Hesperbot_A{
	meta:
		description = "PWS:Win32/Hesperbot.A,SIGNATURE_TYPE_PEHSTR,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_01_0 = {8b c6 c1 e0 0b 33 c6 8b f3 8b df 8b f9 c1 ef 0b 33 f8 c1 ef 08 33 f8 89 4d ec 33 cf 89 5d e8 89 4d f8 83 fa 04 } //5
		$a_01_1 = {63 6f 72 65 5f 78 38 36 2e 62 69 6e } //5 core_x86.bin
		$a_01_2 = {5f 68 65 73 70 65 72 75 73 5f 63 6f 72 65 5f 65 6e 74 72 79 } //5 _hesperus_core_entry
		$a_01_3 = {70 00 74 00 2d 00 62 00 6f 00 74 00 6e 00 65 00 74 00 } //3 pt-botnet
		$a_01_4 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 \Microsoft\Cryptography
		$a_01_5 = {5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 \Windows NT\CurrentVersion
		$a_01_6 = {49 6e 73 74 61 6c 6c 44 61 74 65 } //3 InstallDate
		$a_01_7 = {44 69 67 69 74 61 6c 50 72 6f 64 75 63 74 49 64 } //3 DigitalProductId
		$a_01_8 = {4d 61 63 68 69 6e 65 47 75 69 64 } //3 MachineGuid
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3) >=27
 
}