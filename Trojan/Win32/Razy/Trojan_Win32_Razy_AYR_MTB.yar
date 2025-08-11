
rule Trojan_Win32_Razy_AYR_MTB{
	meta:
		description = "Trojan:Win32/Razy.AYR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 fa 83 ec 04 c7 04 24 ?? ?? ?? ?? 09 d1 81 e9 ?? ?? ?? ?? 21 fe ff d3 81 c7 ?? ?? ?? ?? 42 29 d7 5b 89 ca f7 d6 89 d7 68 ?? ?? ?? ?? 46 09 f2 f7 d2 50 42 29 d1 ff d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}