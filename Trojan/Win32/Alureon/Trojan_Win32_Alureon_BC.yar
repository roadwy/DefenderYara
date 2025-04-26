
rule Trojan_Win32_Alureon_BC{
	meta:
		description = "Trojan:Win32/Alureon.BC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {85 c0 74 02 ff e0 c3 } //1
		$a_01_1 = {8d 8d 00 fe ff ff 51 56 ff d0 } //1
		$a_01_2 = {2c 38 35 2e 32 35 35 2e } //1 ,85.255.
		$a_01_3 = {66 61 63 65 73 5c 25 73 } //1 faces\%s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}