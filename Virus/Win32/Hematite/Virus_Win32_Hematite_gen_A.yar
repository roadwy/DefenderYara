
rule Virus_Win32_Hematite_gen_A{
	meta:
		description = "Virus:Win32/Hematite.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 ef ff 75 10 ff 95 ?? ?? 00 00 ff 75 ?? ff 95 ?? ?? 00 00 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 81 c1 ?? ?? 00 00 e8 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}