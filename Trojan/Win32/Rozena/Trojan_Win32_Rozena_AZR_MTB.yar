
rule Trojan_Win32_Rozena_AZR_MTB{
	meta:
		description = "Trojan:Win32/Rozena.AZR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b f8 89 45 f8 33 f6 57 8d 45 fc 50 ff b6 ?? ?? ?? ?? ff d3 83 c6 04 83 c7 10 81 fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}