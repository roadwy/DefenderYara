
rule Trojan_Win32_Guloader_GPI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {72 6f 65 73 20 73 75 62 74 72 61 68 65 72 65 64 65 20 66 6c 6f 63 6b 73 } //1 roes subtraherede flocks
		$a_81_1 = {75 6e 63 6f 72 6f 6e 65 74 65 64 20 70 75 6c 6c 6f 75 74 2e 65 78 65 } //1 uncoroneted pullout.exe
		$a_81_2 = {75 6e 63 6f 6d 70 61 73 73 65 64 20 61 6e 6b 6c 65 74 } //1 uncompassed anklet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}