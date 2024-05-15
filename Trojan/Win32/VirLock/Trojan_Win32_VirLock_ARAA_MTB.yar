
rule Trojan_Win32_VirLock_ARAA_MTB{
	meta:
		description = "Trojan:Win32/VirLock.ARAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 47 49 e9 d7 ff ff ff } //02 00 
		$a_01_1 = {83 f9 00 0f 85 12 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}