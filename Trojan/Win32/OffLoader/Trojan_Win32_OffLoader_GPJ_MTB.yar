
rule Trojan_Win32_OffLoader_GPJ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_80_0 = {61 64 76 61 6e 63 65 64 6d 61 6e 61 67 65 72 2e 69 6f 2f 65 75 6c 61 } //advancedmanager.io/eula  5
		$a_80_1 = {64 69 67 69 74 61 6c 70 75 6c 73 65 64 61 74 61 2e 63 6f 6d 2f 74 6f 73 } //digitalpulsedata.com/tos  2
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*2) >=7
 
}