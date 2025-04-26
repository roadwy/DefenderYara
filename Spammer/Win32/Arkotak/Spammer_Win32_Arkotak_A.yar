
rule Spammer_Win32_Arkotak_A{
	meta:
		description = "Spammer:Win32/Arkotak.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 6f 74 73 2f 75 70 64 61 74 65 2e 70 68 70 3f 69 64 3d 25 73 26 63 72 63 33 32 3d 25 75 26 76 3d 25 73 } //1 bots/update.php?id=%s&crc32=%u&v=%s
		$a_01_1 = {75 70 64 61 74 65 5f 67 69 66 2e 70 68 70 3f 69 64 3d 25 73 26 74 61 73 6b 5f 69 64 3d 25 73 } //1 update_gif.php?id=%s&task_id=%s
		$a_01_2 = {70 72 6f 63 65 65 64 5f 74 61 73 6b 2e 70 68 70 3f 69 64 3d 25 73 26 74 61 73 6b 5f 69 64 3d 25 73 } //1 proceed_task.php?id=%s&task_id=%s
		$a_01_3 = {72 65 70 6f 72 74 2e 70 68 70 3f 69 64 3d 25 73 26 74 61 73 6b 5f 69 64 3d 25 73 26 73 65 6e 64 3d 25 73 26 74 6f 74 61 6c 5f 64 6f 6e 65 3d 25 69 26 73 65 6e 64 5f 73 75 63 63 65 73 73 3d 25 69 } //1 report.php?id=%s&task_id=%s&send=%s&total_done=%i&send_success=%i
		$a_01_4 = {80 34 30 42 40 3b c7 7e f7 } //1
		$a_03_5 = {80 fa 44 89 45 60 c6 45 67 01 0f 84 ?? ?? ?? ?? 80 fa 56 0f 84 ?? ?? ?? ?? 66 81 39 4c 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=3
 
}