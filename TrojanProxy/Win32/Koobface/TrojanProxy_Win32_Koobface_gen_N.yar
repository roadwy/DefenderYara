
rule TrojanProxy_Win32_Koobface_gen_N{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 29 32 54 24 20 88 11 49 48 75 f3 } //1
		$a_01_1 = {63 66 67 6f 72 6d 64 2e 64 6c 6c } //1 cfgormd.dll
		$a_03_2 = {6a 04 58 39 45 08 a3 ?? ?? ?? ?? 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}