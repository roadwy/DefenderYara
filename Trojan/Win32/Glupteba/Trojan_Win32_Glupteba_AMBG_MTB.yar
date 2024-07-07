
rule Trojan_Win32_Glupteba_AMBG_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AMBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8d 3c 13 81 c3 90 01 04 03 45 dc 33 c7 31 45 fc 8b 45 fc 29 45 f0 ff 4d e8 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}