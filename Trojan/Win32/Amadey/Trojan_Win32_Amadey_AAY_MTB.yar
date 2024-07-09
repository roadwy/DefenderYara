
rule Trojan_Win32_Amadey_AAY_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 38 c7 85 ?? ?? ?? ?? a3 95 05 16 c7 85 ?? ?? ?? ?? 6c 46 ba 09 c7 85 ?? ?? ?? ?? c7 a4 ad 16 c7 85 ?? ?? ?? ?? 55 96 03 5f c7 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}