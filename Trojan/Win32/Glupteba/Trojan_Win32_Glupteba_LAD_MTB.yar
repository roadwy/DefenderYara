
rule Trojan_Win32_Glupteba_LAD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.LAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 ?? 8b c8 8b 45 ?? 31 45 fc 31 ?? fc 2b 5d fc 81 c6 ?? ?? ?? ?? ff 4d e4 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}