
rule Trojan_Win32_Xpack_B_MTB{
	meta:
		description = "Trojan:Win32/Xpack.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 38 4e 65 6f } //2 One8Neo
		$a_01_1 = {54 77 6f 38 4e 65 6f } //2 Two8Neo
		$a_01_2 = {54 68 72 38 4e 65 6f } //2 Thr8Neo
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}