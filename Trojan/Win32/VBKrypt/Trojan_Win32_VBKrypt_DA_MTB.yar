
rule Trojan_Win32_VBKrypt_DA_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //03 00  DllRegisterServer
		$a_01_1 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 57 } //03 00  CallWindowProcW
		$a_01_2 = {70 00 30 00 35 00 6b 00 71 00 34 00 79 00 38 00 59 00 31 00 59 00 4e 00 58 00 } //03 00  p05kq4y8Y1YNX
		$a_01_3 = {62 00 67 00 6b 00 35 00 70 00 35 00 72 00 32 00 57 00 32 00 50 00 30 00 49 00 34 00 42 00 32 00 78 00 69 00 } //03 00  bgk5p5r2W2P0I4B2xi
		$a_01_4 = {56 42 52 55 4e } //03 00  VBRUN
		$a_01_5 = {46 6f 72 6d 5f 4c 6f 61 64 } //00 00  Form_Load
	condition:
		any of ($a_*)
 
}