
rule Virus_Win32_Sality_AM{
	meta:
		description = "Virus:Win32/Sality.AM,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {25 ff 00 00 00 8b 8d ?? ?? ff ff 81 e1 ff 00 00 00 0f af c1 05 38 04 00 00 66 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 52 68 00 04 01 00 6a 00 6a 04 6a 00 6a ff ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}