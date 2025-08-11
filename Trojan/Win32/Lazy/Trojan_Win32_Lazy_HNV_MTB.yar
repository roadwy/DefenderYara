
rule Trojan_Win32_Lazy_HNV_MTB{
	meta:
		description = "Trojan:Win32/Lazy.HNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 00 5c 00 5c 00 25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 5c 00 25 00 6c 00 73 00 2e 00 65 00 78 00 65 00 00 00 } //10
		$a_01_1 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //2 CreateToolhelp32Snapshot
		$a_01_2 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 57 } //1 GetComputerNameW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=13
 
}