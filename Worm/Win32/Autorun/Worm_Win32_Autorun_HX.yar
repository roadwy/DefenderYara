
rule Worm_Win32_Autorun_HX{
	meta:
		description = "Worm:Win32/Autorun.HX,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 72 75 6e 2e 69 6e 66 20 2b 68 20 2b 72 20 2b 73 } //10 autorun.inf +h +r +s
		$a_01_1 = {00 6d 6d 2e 65 78 65 20 2b 68 20 2b 72 20 2b 73 } //1
		$a_01_2 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 } //1 shell\explore\Command
		$a_01_3 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 \Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_4 = {66 31 32 36 2e 63 6f 6d 2f 67 6f 2f } //1 f126.com/go/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}