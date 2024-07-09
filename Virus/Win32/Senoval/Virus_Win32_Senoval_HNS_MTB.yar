
rule Virus_Win32_Senoval_HNS_MTB{
	meta:
		description = "Virus:Win32/Senoval.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 81 ec ?? 00 00 00 60 e8 00 00 00 00 8f 85 [0-12] 29 85 } //2
		$a_03_1 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 } //2
		$a_03_2 = {ff d3 c9 c3 90 09 06 00 03 8d } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}