
rule Trojan_Win32_StealC_SHR_MTB{
	meta:
		description = "Trojan:Win32/StealC.SHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f3 d3 ee 03 c3 89 45 ?? 03 75 dc 8b 45 e4 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //1
		$a_03_1 = {31 75 fc 8b 45 fc 29 45 ec 8b 45 d8 29 45 ?? ff 4d e0 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}