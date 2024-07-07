
rule HackTool_Win32_DesktopImgDownldr{
	meta:
		description = "HackTool:Win32/DesktopImgDownldr,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {20 00 2f 00 6c 00 6f 00 63 00 6b 00 73 00 63 00 72 00 65 00 65 00 6e 00 75 00 72 00 6c 00 3a 00 68 00 74 00 74 00 70 00 90 02 02 3a 00 2f 00 2f 00 90 00 } //1
		$a_00_1 = {20 00 2f 00 65 00 76 00 65 00 6e 00 74 00 4e 00 61 00 6d 00 65 00 3a 00 } //1  /eventName:
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}