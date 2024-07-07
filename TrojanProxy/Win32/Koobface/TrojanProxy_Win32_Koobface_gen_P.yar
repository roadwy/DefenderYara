
rule TrojanProxy_Win32_Koobface_gen_P{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 fc 55 c6 45 fd 0d } //1
		$a_03_1 = {75 0f 47 83 c6 32 3b 7c 24 90 03 01 01 10 14 7c e5 90 00 } //1
		$a_03_2 = {50 44 52 56 2e 64 6c 6c 00 90 03 0c 0b 53 65 72 76 69 63 65 4d 61 69 6e 00 3f 6e 66 5f 61 64 64 52 75 6c 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}