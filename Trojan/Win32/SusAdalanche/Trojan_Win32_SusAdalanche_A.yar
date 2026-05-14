
rule Trojan_Win32_SusAdalanche_A{
	meta:
		description = "Trojan:Win32/SusAdalanche.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {61 64 61 6c 61 6e 63 68 65 2d 63 6f 6c 6c 65 63 74 6f 72 2e 65 78 65 } //adalanche-collector.exe  1
		$a_80_1 = {2d 2d 6f 75 74 70 75 74 70 61 74 68 } //--outputpath  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}