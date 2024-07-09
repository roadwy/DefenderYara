
rule Trojan_Win32_DxmStrt_J_ibt{
	meta:
		description = "Trojan:Win32/DxmStrt.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 76 63 68 6f 73 74 2e 52 65 73 6f 75 72 63 65 73 } //1 svchost.Resources
		$a_00_1 = {64 00 78 00 6d 00 77 00 76 00 } //1 dxmwv
		$a_00_2 = {41 6e 74 69 54 61 73 6b 4d 61 6e 61 67 65 72 4b 69 6c 6c } //1 AntiTaskManagerKill
		$a_02_3 = {2b 43 03 28 29 00 00 0a 80 07 00 00 04 7e 07 00 00 04 8e b7 16 fe 02 0b 07 2c 12 72 ?? 00 00 70 28 31 00 00 0a 28 32 00 00 0a 00 2b 16 00 73 33 00 00 0a 0a 06 02 6f 34 00 00 0a 00 06 28 35 00 00 0a 26 00 00 17 0b 07 2d b8 00 2a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}