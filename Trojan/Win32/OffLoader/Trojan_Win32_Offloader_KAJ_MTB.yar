
rule Trojan_Win32_Offloader_KAJ_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 6c 61 63 65 62 69 74 2e 78 79 7a } ///lacebit.xyz  1
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}