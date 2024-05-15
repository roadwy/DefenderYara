
rule Trojan_Win64_DllInject_PD_MTB{
	meta:
		description = "Trojan:Win64/DllInject.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 02 41 88 00 88 0a 0f b6 54 24 31 44 0f b6 44 24 30 0f b6 4c 14 32 42 02 4c 04 32 0f b6 c1 0f b6 4c 04 32 42 32 4c 16 f7 41 88 4a ff } //00 00 
	condition:
		any of ($a_*)
 
}