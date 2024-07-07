
rule TrojanSpy_Win32_Rebhip_A_upx{
	meta:
		description = "TrojanSpy:Win32/Rebhip.A!upx,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {78 5f 58 5f 42 4c 4f 43 4b 4d 4f 55 53 45 } //3 x_X_BLOCKMOUSE
		$a_01_1 = {2e 61 62 63 00 } //3
		$a_01_2 = {43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 2d 00 43 00 47 00 } //1 CG-CG-CG-CG
		$a_01_3 = {58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 2d 00 58 00 58 00 } //1 XX-XX-XX-XX
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}