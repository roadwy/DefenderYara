
rule Trojan_Win32_Qbot_PAN_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_03_0 = {8b 46 1c 2a 4c 24 90 01 01 03 c3 32 4c 24 90 01 01 83 7c 24 34 90 01 01 88 0c 90 01 01 0f 84 90 01 04 8b 56 1c b0 01 8b 4c 24 34 03 d3 d2 e0 fe c8 8a 14 3a 90 00 } //10
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {41 4e 64 46 32 32 36 4a 34 71 } //1 ANdF226J4q
		$a_01_3 = {49 50 61 35 37 39 } //1 IPa579
		$a_01_4 = {4f 59 52 43 43 34 33 79 37 } //1 OYRCC43y7
		$a_01_5 = {51 45 59 30 57 6f 37 } //1 QEY0Wo7
		$a_01_6 = {50 71 78 4c 54 69 76 42 } //1 PqxLTivB
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=14
 
}