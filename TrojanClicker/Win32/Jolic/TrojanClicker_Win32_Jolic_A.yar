
rule TrojanClicker_Win32_Jolic_A{
	meta:
		description = "TrojanClicker:Win32/Jolic.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 8b ce e8 90 01 04 8b f0 8b 45 90 01 01 3d 74 70 6c 00 90 00 } //1
		$a_02_1 = {59 8b f0 e9 90 01 04 3c 3c 0f 85 90 01 04 81 7f 90 01 01 73 74 6f 70 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}