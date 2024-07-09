
rule PWS_Win32_Lolyda_P{
	meta:
		description = "PWS:Win32/Lolyda.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {7c 4c 8b 0d ?? ?? ?? ?? 83 f9 01 7c 41 81 f9 96 00 00 00 7f 39 56 8b 35 ?? ?? ?? ?? 6a 0a } //1
		$a_00_1 = {73 65 72 76 65 72 3d 25 73 26 61 63 63 6f 75 6e 74 3d 25 73 26 70 61 73 73 77 6f 72 64 31 3d 25 73 26 70 61 73 73 77 6f 72 64 32 3d 25 73 26 6c 65 76 65 6c 73 3d 25 73 26 63 61 73 68 3d 25 73 26 } //1 server=%s&account=%s&password1=%s&password2=%s&levels=%s&cash=%s&
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}