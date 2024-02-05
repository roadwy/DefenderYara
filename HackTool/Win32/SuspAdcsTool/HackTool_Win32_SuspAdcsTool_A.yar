
rule HackTool_Win32_SuspAdcsTool_A{
	meta:
		description = "HackTool:Win32/SuspAdcsTool.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {66 69 6e 64 20 2f 76 75 6c 6e 65 72 61 62 6c 65 } //find /vulnerable  01 00 
		$a_80_1 = {56 75 6c 6e 65 72 61 62 6c 65 20 43 65 72 74 69 66 69 63 61 74 65 73 20 54 65 6d 70 6c 61 74 65 73 } //Vulnerable Certificates Templates  01 00 
		$a_80_2 = {2f 65 6e 72 6f 6c 6c 63 65 72 74 3a 43 3a 5c 54 65 6d 70 5c 65 6e 72 6f 6c 6c 2e 70 66 78 } ///enrollcert:C:\Temp\enroll.pfx  00 00 
	condition:
		any of ($a_*)
 
}