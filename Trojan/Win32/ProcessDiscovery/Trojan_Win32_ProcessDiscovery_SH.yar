
rule Trojan_Win32_ProcessDiscovery_SH{
	meta:
		description = "Trojan:Win32/ProcessDiscovery.SH,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_80_0 = {26 20 74 61 73 6b 6c 69 73 74 20 2f 6d 20 26 } //& tasklist /m &  1
		$a_80_1 = {26 20 74 61 73 6b 6c 69 73 74 20 2f 73 76 63 20 26 } //& tasklist /svc &  1
		$a_80_2 = {26 20 74 61 73 6b 6c 69 73 74 20 2f 76 20 26 } //& tasklist /v &  1
		$a_80_3 = {26 20 65 63 68 6f 20 23 23 23 23 74 61 73 6b 6c 69 73 74 23 23 23 23 } //& echo ####tasklist####  -10
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-10) >=1
 
}