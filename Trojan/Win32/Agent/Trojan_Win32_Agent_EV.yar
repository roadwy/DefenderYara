
rule Trojan_Win32_Agent_EV{
	meta:
		description = "Trojan:Win32/Agent.EV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //1 \Device\PhysicalMemory
		$a_03_1 = {8b 45 08 a3 90 01 04 8b 45 0c ff 1d 90 01 04 8b 45 0c 8b 4d 08 50 51 6a 00 e8 90 00 } //1
		$a_03_2 = {0f 01 45 f8 8b 4d fa 8d 45 08 50 51 e8 90 01 02 ff ff 8b 75 f8 8b 55 08 81 e6 ff ff 00 00 83 c4 08 8d 0c 16 51 50 6a 00 6a 06 57 ff 15 90 01 04 85 c0 a3 90 01 04 75 08 5f 32 c0 5e 8b e5 5d c3 8b 55 08 bf 00 ff 00 00 8d 4c 10 08 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}