
rule TrojanSpy_Win32_Rebhip_A_upx{
	meta:
		description = "TrojanSpy:Win32/Rebhip.A!upx,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {78 5f 58 5f 42 4c 4f 43 4b 4d 4f 55 53 45 } //03 00 
		$a_01_1 = {2e 61 62 63 00 } //01 00 
		$a_01_2 = {43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 } //01 00 
		$a_01_3 = {58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 } //00 00 
		$a_00_4 = {5d 04 00 00 b1 2b } //03 80 
	condition:
		any of ($a_*)
 
}