
rule Trojan_Win32_VB_OB{
	meta:
		description = "Trojan:Win32/VB.OB,SIGNATURE_TYPE_PEHSTR,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 00 73 76 63 68 6f 73 74 00 00 43 6c 69 63 6b 41 64 73 42 79 49 45 5f 43 6c 69 65 6e 74 } //10 浣d癳档獯t䌀楬正摁䉳䥹彅汃敩瑮
		$a_01_1 = {70 00 6b 00 2e 00 78 00 69 00 61 00 6f 00 70 00 6f 00 68 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 } //10 pk.xiaopohai.com
		$a_01_2 = {2d 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 2d 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 2d 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 2d 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 2d 00 52 00 75 00 6e 00 } //10 -SOFTWARE\-Microsoft\-Windows\-CurrentVersion\-Run
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}