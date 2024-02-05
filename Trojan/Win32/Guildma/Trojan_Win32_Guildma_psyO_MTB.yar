
rule Trojan_Win32_Guildma_psyO_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 90 88 07 90 46 90 e9 00 00 00 00 47 90 49 90 83 f9 00 90 0f 85 e3 ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}