
rule Trojan_Win32_Fauppod_PC_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 3a 00 74 90 02 04 ac 32 02 88 07 47 51 83 c4 90 01 01 42 89 c0 56 83 c4 90 01 01 83 e9 90 01 01 89 c0 85 c9 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}