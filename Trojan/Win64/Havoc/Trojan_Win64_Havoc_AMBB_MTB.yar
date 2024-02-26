
rule Trojan_Win64_Havoc_AMBB_MTB{
	meta:
		description = "Trojan:Win64/Havoc.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {45 31 d1 41 31 c1 44 89 c0 45 01 c0 c0 e8 07 45 31 cf 44 8a 4a fe 41 0f af c4 44 88 7a fd 45 31 d1 44 32 52 ff 41 31 c1 89 c8 01 c9 c0 e8 07 45 31 c8 41 0f af c4 44 88 42 fe 45 89 d0 44 31 c0 31 c1 88 4a ff } //00 00 
	condition:
		any of ($a_*)
 
}