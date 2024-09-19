
rule Trojan_Win32_Offloader_KAI_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 73 74 65 65 6c 74 65 61 6d 2e 78 79 7a } ///steelteam.xyz  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}