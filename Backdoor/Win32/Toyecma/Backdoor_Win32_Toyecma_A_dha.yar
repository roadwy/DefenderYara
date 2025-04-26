
rule Backdoor_Win32_Toyecma_A_dha{
	meta:
		description = "Backdoor:Win32/Toyecma.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 57 49 4e 5d 00 00 00 5b 43 54 52 4c 5d 00 } //1
		$a_01_1 = {5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 } //1 [%02d/%02d/%d %02d:%02d:%02d] (%s)
		$a_00_2 = {74 76 74 73 76 63 20 69 73 20 72 75 6e 6e 69 6e 67 } //1 tvtsvc is running
		$a_03_3 = {0f b6 59 01 88 1c 08 0f b6 19 fe cb 88 5c 37 01 83 c6 02 83 c1 02 3b f2 7e ?? 8b ?? ?? 8b ?? ?? 8b c3 25 01 00 00 80 79 ?? 48 83 c8 fe 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}