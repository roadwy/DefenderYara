
rule Trojan_Win32_Gandcrab_VZD_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.VZD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 75 6d 61 6a 61 6d 65 70 6f 7a 6f 74 65 72 61 } //1 wumajamepozotera
		$a_02_1 = {c0 e1 04 0a 4f ?? c0 e2 06 0a 57 ?? 88 04 1e 46 88 0c 1e 8b 4c 24 ?? 46 88 14 1e 83 c5 04 46 3b 29 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}