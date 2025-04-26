
rule Trojan_Win32_Seorhick_EA{
	meta:
		description = "Trojan:Win32/Seorhick.EA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {66 00 61 00 63 00 65 00 66 00 6f 00 64 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 facefoduninstaller.exe
	condition:
		((#a_00_0  & 1)*1) >=1
 
}