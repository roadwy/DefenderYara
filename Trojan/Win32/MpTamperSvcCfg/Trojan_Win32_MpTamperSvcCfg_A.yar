
rule Trojan_Win32_MpTamperSvcCfg_A{
	meta:
		description = "Trojan:Win32/MpTamperSvcCfg.A,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 63 00 2e 00 65 00 78 00 65 00 } //5 \windows\system32\sc.exe
		$a_00_1 = {73 00 64 00 73 00 65 00 74 00 20 00 } //5 sdset 
		$a_00_2 = {77 00 64 00 66 00 69 00 6c 00 74 00 65 00 72 00 20 00 } //1 wdfilter 
		$a_00_3 = {6d 00 73 00 73 00 65 00 63 00 66 00 6c 00 74 00 20 00 } //1 mssecflt 
		$a_00_4 = {73 00 67 00 72 00 6d 00 61 00 67 00 65 00 6e 00 74 00 20 00 } //1 sgrmagent 
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=11
 
}