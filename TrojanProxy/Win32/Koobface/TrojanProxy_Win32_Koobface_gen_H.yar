
rule TrojanProxy_Win32_Koobface_gen_H{
	meta:
		description = "TrojanProxy:Win32/Koobface.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {59 53 c6 45 90 01 01 31 c6 45 90 01 01 32 c6 45 90 01 01 37 c6 45 90 01 01 2e 90 00 } //2
		$a_03_1 = {68 95 1f 00 00 aa e8 90 01 02 ff ff 90 00 } //2
		$a_03_2 = {4f 4f f7 df 1b ff 83 e7 0a 69 ff e8 03 00 00 59 57 ff 15 90 01 02 40 00 5f 5e 5b c9 c3 90 00 } //1
		$a_00_3 = {61 64 44 20 22 68 6b 4c 6d 5c } //1 adD "hkLm\
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}