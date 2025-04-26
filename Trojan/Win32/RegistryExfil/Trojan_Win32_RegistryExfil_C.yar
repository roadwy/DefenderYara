
rule Trojan_Win32_RegistryExfil_C{
	meta:
		description = "Trojan:Win32/RegistryExfil.C,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //10 reg.exe
		$a_00_1 = {68 00 6b 00 6c 00 6d 00 5c 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } //10 hklm\security
		$a_00_2 = {63 00 6f 00 70 00 79 00 } //1 copy
		$a_00_3 = {73 00 61 00 76 00 65 00 } //1 save
		$a_00_4 = {65 00 78 00 70 00 6f 00 72 00 74 00 } //1 export
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=21
 
}