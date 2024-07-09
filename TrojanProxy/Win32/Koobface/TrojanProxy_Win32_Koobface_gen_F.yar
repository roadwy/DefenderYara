
rule TrojanProxy_Win32_Koobface_gen_F{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 1e 50 68 ?? ?? 22 00 53 ff d7 } //1
		$a_01_1 = {c6 45 fc 55 c6 45 fd 0d } //1
		$a_01_2 = {59 75 12 46 83 c7 32 3b 74 24 10 7c e8 } //1
		$a_01_3 = {73 66 78 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}