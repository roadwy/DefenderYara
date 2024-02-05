
rule Ransom_Win32_Gandcrab_RPF_MTB{
	meta:
		description = "Ransom:Win32/Gandcrab.RPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40 30 8a 90 01 04 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40 30 8a 90 01 04 33 c9 83 f8 0b 0f 44 c1 0f b6 4c 85 84 40 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}