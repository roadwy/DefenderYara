
rule Trojan_Win32_SuspCodeExec_E{
	meta:
		description = "Trojan:Win32/SuspCodeExec.E,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {26 20 70 63 61 6c 75 61 2e 65 78 65 20 2d 61 20 } //& pcalua.exe -a   1
		$a_80_1 = {20 2d 63 20 5c 5c 2e 5c 70 69 70 65 5c 6d 6f 76 65 } // -c \\.\pipe\move  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}