
rule Trojan_Win32_Guildma_psyE_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {57 51 81 ef 90 02 2f 83 e8 05 89 45 f4 74 08 b8 90 02 06 89 45 f4 33 4d f4 83 ea 01 75 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}