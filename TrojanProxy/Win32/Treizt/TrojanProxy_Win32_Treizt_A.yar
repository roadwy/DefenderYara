
rule TrojanProxy_Win32_Treizt_A{
	meta:
		description = "TrojanProxy:Win32/Treizt.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 63 6f 6e 66 69 67 2e 73 74 72 65 61 6d 00 } //1
		$a_00_1 = {73 72 63 5f 68 74 74 70 5f 70 6f 72 74 } //1 src_http_port
		$a_03_2 = {6a 04 8d 4d ?? 51 68 80 00 00 00 68 ff ff 00 00 50 ff 15 ?? ?? ?? ?? 8b 8e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}