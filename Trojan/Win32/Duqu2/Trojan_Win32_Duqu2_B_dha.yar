
rule Trojan_Win32_Duqu2_B_dha{
	meta:
		description = "Trojan:Win32/Duqu2.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 04 00 00 "
		
	strings :
		$a_01_0 = {8d 16 8b 1a f7 db 0f cb c1 c3 03 0f cb 81 f3 } //100
		$a_00_1 = {26 00 61 00 3d 00 6d 00 6f 00 75 00 73 00 65 00 } //1 &a=mouse
		$a_00_2 = {64 00 65 00 6c 00 61 00 79 00 65 00 64 00 2d 00 61 00 75 00 74 00 6f 00 } //1 delayed-auto
		$a_00_3 = {53 00 50 00 25 00 64 00 25 00 63 00 } //1 SP%d%c
	condition:
		((#a_01_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=102
 
}