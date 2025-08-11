
rule Trojan_Win32_DomainEnum_ZZZ_MTB{
	meta:
		description = "Trojan:Win32/DomainEnum.ZZZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 75 00 73 00 65 00 72 00 73 00 } //1 domain users
		$a_00_1 = {2f 00 64 00 6f 00 6d 00 61 00 69 00 6e 00 20 00 3e 00 } //1 /domain >
		$a_02_2 = {74 00 65 00 6d 00 70 00 [0-3c] 2e 00 74 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}