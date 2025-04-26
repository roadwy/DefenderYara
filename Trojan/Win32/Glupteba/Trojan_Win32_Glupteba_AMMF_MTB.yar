
rule Trojan_Win32_Glupteba_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 03 c2 89 4d ?? 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 89 45 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}