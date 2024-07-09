
rule PWS_Win32_Witkinat_A{
	meta:
		description = "PWS:Win32/Witkinat.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 60 ea 00 00 73 ?? 68 ff 7f 00 00 b9 ?? ?? ?? ?? 8d 85 00 80 fd ff ba ff ff 00 00 e8 } //1
		$a_03_1 = {ba 00 00 01 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 68 82 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 f3 7f fe ff 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}