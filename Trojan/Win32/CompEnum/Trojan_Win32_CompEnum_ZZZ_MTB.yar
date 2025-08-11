
rule Trojan_Win32_CompEnum_ZZZ_MTB{
	meta:
		description = "Trojan:Win32/CompEnum.ZZZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 63 00 6f 00 4d 00 } //1 owershell -coM
		$a_02_1 = {74 00 65 00 6d 00 70 00 [0-ff] 2e 00 74 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}