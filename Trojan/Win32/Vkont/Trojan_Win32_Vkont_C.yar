
rule Trojan_Win32_Vkont_C{
	meta:
		description = "Trojan:Win32/Vkont.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 68 6f 73 74 73 5c 72 65 6c 65 61 73 65 5c 68 6f 73 74 73 2e 70 64 62 } //1 \hosts\release\hosts.pdb
		$a_00_1 = {44 41 54 41 3a 20 25 78 20 25 78 20 25 78 20 25 78 20 25 78 20 25 78 21 } //1 DATA: %x %x %x %x %x %x!
		$a_02_2 = {0f 84 a4 00 00 00 8b ?? ?? 0f ?? ?? ?? ?? 81 fa cc 00 00 00 0f 84 90 90 00 00 00 8b ?? ?? 8b 88 0c 02 00 00 8b ?? ?? c6 04 11 e9 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}