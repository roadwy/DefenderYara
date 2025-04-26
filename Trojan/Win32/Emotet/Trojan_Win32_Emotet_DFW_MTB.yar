
rule Trojan_Win32_Emotet_DFW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 18 83 c5 01 c7 84 24 ?? ?? ?? ?? ff ff ff ff 0f b6 94 14 ?? ?? ?? ?? 30 55 ff } //1
		$a_81_1 = {32 39 77 78 46 76 6c 79 57 64 6c 55 78 49 75 6d 65 33 48 54 75 68 35 41 6b 46 49 35 74 4d 35 6b 79 4f 30 72 6d } //1 29wxFvlyWdlUxIume3HTuh5AkFI5tM5kyO0rm
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}