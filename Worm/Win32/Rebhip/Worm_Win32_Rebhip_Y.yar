
rule Worm_Win32_Rebhip_Y{
	meta:
		description = "Worm:Win32/Rebhip.Y,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 00 31 00 38 00 32 00 37 00 33 00 36 00 34 00 35 00 30 00 7a 00 61 00 79 00 62 00 78 00 63 00 77 00 64 00 76 00 65 00 75 00 66 00 74 00 67 00 73 00 68 00 72 00 69 00 71 00 6a 00 70 00 6b 00 6f 00 6c 00 6d 00 6e 00 5a 00 41 00 } //1 9182736450zaybxcwdveuftgshriqjpkolmnZA
		$a_01_1 = {66 72 6d 4c 6f 67 69 6e } //1 frmLogin
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}