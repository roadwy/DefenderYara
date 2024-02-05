
rule Trojan_Win64_Emotet_AL_MTB{
	meta:
		description = "Trojan:Win64/Emotet.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f b6 04 1f 42 32 04 2f 88 04 3e 48 83 c7 01 48 81 ff } //00 00 
	condition:
		any of ($a_*)
 
}