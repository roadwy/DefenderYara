
rule TrojanProxy_Win32_Koobface_gen_G{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 25 c6 45 ?? 55 c6 45 ?? 0d c6 45 ?? ec } //1
		$a_01_1 = {59 75 0f 46 83 c7 32 3b 74 24 10 7c e6 } //1
		$a_01_2 = {00 50 4e 50 5f 54 44 49 00 7a 6f 6e 65 6c 6f 67 00 7a 6f 6e 65 6c 61 62 73 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}