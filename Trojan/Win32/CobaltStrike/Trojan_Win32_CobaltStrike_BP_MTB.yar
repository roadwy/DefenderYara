
rule Trojan_Win32_CobaltStrike_BP_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b8 39 8e e3 38 f7 e7 8b c7 47 c1 ea 03 8d 0c d2 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 06 3b fb 72 } //1
		$a_01_1 = {41 56 42 79 70 61 73 73 2e 70 64 62 } //1 AVBypass.pdb
		$a_01_2 = {68 74 74 70 5f 64 6c 6c 2e 64 61 74 } //1 http_dll.dat
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}