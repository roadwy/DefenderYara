
rule Trojan_Win32_Dogrobot_gen_E{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!E,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {be 8b ff 55 8b 39 30 75 16 81 78 04 ec 5d ff 25 75 0d 8b 50 08 8b 0a } //1
		$a_01_1 = {66 81 38 ff 25 89 45 d0 c6 45 ff 01 74 06 c6 45 ff 00 eb 0b } //1
		$a_01_2 = {81 78 0c 04 3c 00 f0 0f 85 } //1
		$a_01_3 = {43 4c 41 53 53 50 4e 50 2e 53 59 53 } //1 CLASSPNP.SYS
		$a_01_4 = {5c 44 65 76 69 63 65 5c 48 61 72 64 64 69 73 6b 30 5c 44 52 30 } //1 \Device\Harddisk0\DR0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}