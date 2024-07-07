
rule Trojan_Win32_Mekotio_YAA_MTB{
	meta:
		description = "Trojan:Win32/Mekotio.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 62 6b 46 43 61 6c 6c 57 72 61 70 70 65 72 41 64 64 72 } //1 dbkFCallWrapperAddr
		$a_01_1 = {5f 5f 64 62 6b 5f 66 63 61 6c 6c 5f 77 72 61 70 70 65 72 } //1 __dbk_fcall_wrapper
		$a_01_2 = {54 4d 65 74 68 6f 64 49 6d 70 6c 65 6d 65 6e 74 61 74 69 6f 6e 49 6e 74 65 72 63 65 70 74 } //1 TMethodImplementationIntercept
		$a_01_3 = {48 40 33 da 03 c9 66 0f a3 c1 13 f2 0f c8 ff e6 } //1
		$a_01_4 = {32 c3 c1 c1 ba 66 0b c9 66 0f a3 c9 d0 c8 66 0f ab c9 fe c1 66 ff c9 32 c1 66 81 e9 92 b2 66 d3 c9 fe c8 2b c9 34 1d c1 e1 92 c0 e1 63 d0 c8 32 d8 66 23 c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}