
rule Worm_Win32_Pushbot_UJ{
	meta:
		description = "Worm:Win32/Pushbot.UJ,SIGNATURE_TYPE_PEHSTR,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 73 20 25 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 } //1 %s %s "" "lol" :%s
		$a_01_1 = {42 6f 74 50 6f 6b 65 } //1 BotPoke
		$a_01_2 = {73 63 61 6e 2e 73 74 6f 70 } //1 scan.stop
		$a_01_3 = {6d 73 6e 68 69 64 64 65 6e 77 69 6e 64 6f 77 63 6c 61 73 73 } //1 msnhiddenwindowclass
		$a_01_4 = {5b 61 75 74 6f 72 75 6e 5d 00 } //1 慛瑵牯湵]
		$a_01_5 = {61 63 74 69 6f 6e 3d 6f 70 65 6e 20 66 6f 6c 64 65 72 20 74 6f 20 76 69 65 77 20 66 69 6c 65 73 } //1 action=open folder to view files
		$a_01_6 = {00 64 64 6f 73 65 72 00 } //1 搀潤敳r
		$a_01_7 = {5c 00 52 00 45 00 43 00 59 00 43 00 4c 00 45 00 52 00 } //1 \RECYCLER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}