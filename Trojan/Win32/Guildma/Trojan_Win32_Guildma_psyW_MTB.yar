
rule Trojan_Win32_Guildma_psyW_MTB{
	meta:
		description = "Trojan:Win32/Guildma.psyW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {89 0d 76 50 50 00 ff 15 14 40 50 00 a3 98 52 50 00 c7 05 20 52 50 00 dd 32 50 00 c7 05 1c 52 50 00 02 00 00 00 eb 04 00 00 00 00 c7 05 24 52 50 00 00 00 00 00 c7 05 28 52 50 00 00 00 00 00 c7 05 18 52 50 00 30 00 00 00 6a 00 ff 15 10 40 50 00 a3 2c 52 50 00 c7 05 40 52 50 00 88 40 50 00 c7 05 38 52 50 00 0f 00 00 00 a3 6e 50 50 00 68 00 7f 00 00 6a 00 ff 15 78 40 50 00 a3 30 52 50 00 a3 44 52 50 00 68 00 7f 00 00 6a 00 ff 15 74 40 50 00 a3 34 52 50 00 } //00 00 
	condition:
		any of ($a_*)
 
}