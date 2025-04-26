
rule Trojan_Win32_ArchiveLock_B{
	meta:
		description = "Trojan:Win32/ArchiveLock.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 6c 73 61 73 73 38 36 76 6c 2e 65 78 65 00 } //1
		$a_00_1 = {73 79 73 74 65 6d 33 32 5c 73 64 65 6c 65 74 65 2e 64 6c 6c } //1 system32\sdelete.dll
		$a_03_2 = {68 a0 bb 0d 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 00 00 00 00 e8 ?? ?? ?? ?? e8 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}