
rule Trojan_Win32_Dukes_BI{
	meta:
		description = "Trojan:Win32/Dukes.BI,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 43 3a 5c 53 67 49 6e 74 66 2e 64 6c 6c 2c 54 61 73 6b 5a 75 74 } //C:\WINDOWS\SYSTEM32\rundll32.exe C:\SgIntf.dll,TaskZut  10
	condition:
		((#a_80_0  & 1)*10) >=10
 
}