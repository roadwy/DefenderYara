
rule Trojan_Win32_Glupteba_DHD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f8 8b 45 ?? d1 6d ?? 29 45 ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 61 01 00 00 5b 90 13 8b 45 ?? 8b 4d ?? 89 48 ?? 8b 4d ?? 89 38 5f 33 cd } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}