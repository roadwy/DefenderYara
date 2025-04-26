
rule Backdoor_Win32_Ripgof_B{
	meta:
		description = "Backdoor:Win32/Ripgof.B,SIGNATURE_TYPE_PEHSTR,33 00 33 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 64 5c 00 63 3a 5c 72 65 63 79 63 6c 00 } //10 摥\㩣牜捥捹l
		$a_01_1 = {4c 69 73 74 65 6e 65 72 20 72 65 61 64 73 20 52 65 6d 6f 74 65 20 52 6f 75 74 69 6e 67 20 49 6e 66 6f 72 6d 61 74 69 6f 6e 20 50 72 6f 74 6f 63 6f 6c 20 28 52 49 50 29 20 70 61 63 6b 65 74 73 } //10 Listener reads Remote Routing Information Protocol (RIP) packets
		$a_01_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 6e 65 74 73 76 63 73 } //10 %SystemRoot%\System32\svchost.exe -k netsvcs
		$a_01_3 = {53 65 72 76 69 63 65 44 6c 6c } //10 ServiceDll
		$a_01_4 = {5c 69 6e 66 5c 69 70 } //10 \inf\ip
		$a_01_5 = {5c 6e 69 70 72 70 2e 64 6c 6c } //1 \niprp.dll
		$a_01_6 = {5c 70 77 66 73 68 2e 64 6c 6c } //1 \pwfsh.dll
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=51
 
}