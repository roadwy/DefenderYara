
rule Trojan_Win32_IcedId_DEP_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8d 45 fc 6a 00 6a 01 6a 00 6a 00 50 c7 45 f8 ?? ?? ?? ?? ff d6 85 c0 75 ?? 6a 08 6a 01 50 50 8d 45 fc 50 ff d6 85 c0 } //1
		$a_81_1 = {30 6f 46 57 39 65 65 4b 72 57 43 50 55 5a 78 45 72 39 69 30 56 75 79 68 6f 77 56 52 70 73 7a 74 52 34 69 42 7a 6c 33 } //1 0oFW9eeKrWCPUZxEr9i0VuyhowVRpsztR4iBzl3
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}