
rule Trojan_Win32_NetworkSniffing_ZPA{
	meta:
		description = "Trojan:Win32/NetworkSniffing.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 00 74 00 73 00 68 00 61 00 72 00 6b 00 2e 00 65 00 78 00 65 00 } //1 \tshark.exe
		$a_00_1 = {20 00 2d 00 69 00 20 00 } //1  -i 
		$a_00_2 = {20 00 2d 00 63 00 20 00 35 00 } //1  -c 5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}