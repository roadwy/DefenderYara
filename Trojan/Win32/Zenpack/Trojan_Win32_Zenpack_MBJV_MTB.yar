
rule Trojan_Win32_Zenpack_MBJV_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c 61 68 61 6e 65 6b 75 63 6f 66 69 6a 61 6a 69 77 61 77 00 73 65 77 6f 6d 65 78 69 6b 69 6a 61 6c 6f 64 65 64 65 6c 65 76 65 20 73 6f 79 75 67 6f 6c 6f 72 61 63 69 20 79 61 6d 61 7a 69 64 00 72 75 6a 65 68 75 6c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}