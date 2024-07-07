
rule Trojan_Win32_Glupteba_DHK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 7d 0c 69 04 00 00 90 13 e8 90 01 04 8b 4d 08 30 04 0e 46 3b 75 0c 7c ac 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}