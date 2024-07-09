
rule Virus_Win32_Expiro_EA_bit{
	meta:
		description = "Virus:Win32/Expiro.EA!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d1 8b 11 85 d2 81 f2 ?? ?? ?? ?? 39 d1 89 10 42 41 4f 41 4f 4f 41 41 4f 81 c0 04 00 00 00 83 ff 00 74 05 e9 d7 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}