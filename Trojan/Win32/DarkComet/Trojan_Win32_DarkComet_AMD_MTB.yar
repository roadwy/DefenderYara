
rule Trojan_Win32_DarkComet_AMD_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 ff d3 6a 0a 6a 64 6a 00 ff d0 68 ?? 8d 41 00 57 89 46 7c ff d3 8b 4e 7c 51 6a 00 ff d0 68 ?? 8d 41 00 57 89 86 ?? ?? ?? ?? ff d3 8b 56 7c 52 6a 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}