
rule Trojan_Win32_Swotter_BC_MTB{
	meta:
		description = "Trojan:Win32/Swotter.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //2 Nullsoft Install System
		$a_02_1 = {25 25 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 90 05 15 03 61 2d 7a 2c 4d 69 6e 79 61 6e 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}