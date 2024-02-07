
rule PWS_Win32_Karsh_A{
	meta:
		description = "PWS:Win32/Karsh.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c0 02 e8 e1 fa ff ff 50 e8 fb fa ff ff 61 e8 e4 fa ff ff ff d0 6a 00 68 ff } //01 00 
		$a_01_1 = {61 64 76 61 70 69 33 32 00 48 54 54 50 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 } //01 00  摡慶楰㈳䠀呔屐桳汥屬灯湥捜
		$a_01_2 = {e8 26 00 00 00 83 e8 0f 5b 8f 00 53 c3 e8 19 00 00 00 eb 04 00 00 00 00 83 c0 } //01 00 
		$a_01_3 = {eb 13 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 83 c0 02 e8 } //01 00 
		$a_01_4 = {eb 13 43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 00 83 c0 02 e8 } //00 00 
	condition:
		any of ($a_*)
 
}