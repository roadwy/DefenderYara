
rule TrojanProxy_Win32_Koobface_gen_L{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 04 29 32 44 24 1c 88 01 49 4f 75 f3 } //2
		$a_01_1 = {63 65 72 74 6f 6b 6f 2e 64 6c 6c } //2 certoko.dll
		$a_01_2 = {2f 75 72 6c 3f } //1 /url?
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=3
 
}