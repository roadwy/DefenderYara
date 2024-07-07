
rule MonitoringTool_MSIL_FewzLogger{
	meta:
		description = "MonitoringTool:MSIL/FewzLogger,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 00 65 00 77 00 7a 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //1 FewzLogger
		$a_01_1 = {2d 00 5f 00 3d 00 28 00 5b 00 21 00 7c 00 20 00 4b 00 65 00 79 00 6c 00 69 00 65 00 65 00 20 00 7c 00 21 00 5d 00 29 00 3d 00 5f 00 2d 00 } //1 -_=([!| Keyliee |!])=_-
		$a_01_2 = {41 00 6e 00 6b 00 61 00 6d 00 61 00 20 00 53 00 68 00 69 00 65 00 6c 00 64 00 20 00 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 } //1 Ankama Shield Stealer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}