
rule Virus_Win32_Mabezat{
	meta:
		description = "Virus:Win32/Mabezat,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec d8 06 00 00 53 56 57 (b8 ?? ?? ?? ?? b9 00 00 00|00 b9 00 00 00 00 b8 ?? ??) ?? ?? 8a ?? 80 ?? ?? 88 ?? 83 ?? 01 83 ?? 01 81 f9 90 90 05 00 00 75 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}