
rule PWS_Win32_Cabalest_A{
	meta:
		description = "PWS:Win32/Cabalest.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 b2 68 32 01 } //1
		$a_01_1 = {80 fb 61 7c 1d 80 fb 7a 7f 18 8b c6 6a 1a 99 5f f7 ff 0f be c3 2b c2 83 e8 47 99 f7 ff 80 c2 61 eb 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}