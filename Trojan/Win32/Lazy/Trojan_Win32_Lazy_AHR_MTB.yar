
rule Trojan_Win32_Lazy_AHR_MTB{
	meta:
		description = "Trojan:Win32/Lazy.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_81_0 = {5c 41 70 70 44 61 74 61 7c 5c 42 6f 6f 74 7c 5c 50 65 72 66 4c 6f 67 73 7c 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 7c 5c 54 65 6d 70 6f 72 61 72 79 } //10 \AppData|\Boot|\PerfLogs|\Program Files|\Temporary
		$a_03_1 = {33 c1 8b 55 d0 8b 4d dc 2b 4a 14 8b 55 d0 8b 52 0c 88 04 0a c7 45 fc ?? ?? ?? ?? eb } //30
		$a_01_2 = {8b 55 c8 33 04 8a 8b 4d 08 8b 11 8b 4d 08 8b 09 8b 75 a8 2b 71 14 8b 52 0c 88 04 32 } //20
	condition:
		((#a_81_0  & 1)*10+(#a_03_1  & 1)*30+(#a_01_2  & 1)*20) >=60
 
}