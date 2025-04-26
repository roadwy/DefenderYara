
rule Trojan_Win32_DataExfiltration_ZPA{
	meta:
		description = "Trojan:Win32/DataExfiltration.ZPA,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 75 00 72 00 6c 00 } //10 curl
		$a_01_1 = {20 00 2d 00 6b 00 20 00 2d 00 46 00 20 00 } //10  -k -F 
		$a_00_2 = {66 00 69 00 6c 00 65 00 3d 00 40 00 } //10 file=@
		$a_00_3 = {20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1  http://
		$a_00_4 = {20 00 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //1  https://
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=31
 
}