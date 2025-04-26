
rule Trojan_Win32_Glupteba_GB_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c1 29 45 ?? 89 75 ?? 81 f3 07 eb dd 13 81 6d 30 ?? ?? ?? ?? b8 41 e5 64 03 81 6d 30 ?? ?? ?? ?? 81 45 30 ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? 8b c2 d3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}