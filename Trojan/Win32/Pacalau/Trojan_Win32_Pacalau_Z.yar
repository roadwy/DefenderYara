
rule Trojan_Win32_Pacalau_Z{
	meta:
		description = "Trojan:Win32/Pacalau.Z,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-05] 2d 00 61 00 [0-20] 2e 00 65 00 78 00 65 00 } //1
		$a_02_1 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-05] 2d 00 61 00 [0-20] 2e 00 64 00 6c 00 6c 00 } //1
		$a_02_2 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-05] 2d 00 61 00 [0-20] 2e 00 63 00 70 00 6c 00 } //1
		$a_02_3 = {70 00 63 00 61 00 6c 00 75 00 61 00 2e 00 65 00 78 00 65 00 [0-3c] 20 00 2d 00 64 00 } //-100
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*-100) >=1
 
}