
rule TrojanSpy_Win32_Delf_CL{
	meta:
		description = "TrojanSpy:Win32/Delf.CL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 2d 44 69 73 70 6f 73 69 74 69 6f 6e 3a 20 66 6f 72 6d 2d 64 61 74 61 3b 20 6e 61 6d 65 3d 22 70 77 64 61 74 61 22 3b 20 66 69 6c 65 6e 61 6d 65 3d 22 70 77 64 61 74 61 22 } //03 00  Content-Disposition: form-data; name="pwdata"; filename="pwdata"
		$a_01_1 = {3f 74 79 70 65 3d 30 26 65 6d 61 69 6c 3d } //03 00  ?type=0&email=
		$a_01_2 = {69 6e 65 74 63 6f 6d 6d 20 73 65 72 76 65 72 20 70 61 73 73 77 6f 72 64 73 } //00 00  inetcomm server passwords
	condition:
		any of ($a_*)
 
}