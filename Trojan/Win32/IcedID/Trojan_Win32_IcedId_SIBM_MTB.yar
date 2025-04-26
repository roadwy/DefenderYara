
rule Trojan_Win32_IcedId_SIBM_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {49 6e 64 75 73 74 72 79 2e 70 64 62 } //1 Industry.pdb
		$a_03_1 = {58 89 44 24 ?? 8b 3b [0-50] 8b 44 24 90 1b 00 81 c7 ?? ?? ?? ?? 89 3b 83 c3 04 48 [0-10] 89 44 24 90 1b 00 75 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}