
rule Trojan_Win32_Glupteba_LAD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.LAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 03 45 90 01 01 8b c8 8b 45 90 01 01 31 45 fc 31 90 01 01 fc 2b 5d fc 81 c6 90 01 04 ff 4d e4 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}