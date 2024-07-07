
rule Trojan_Win32_Glupteba_MS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 4d dc 51 ff 15 90 01 04 8b 55 90 01 01 8b 45 90 01 01 33 c6 8b 75 90 01 01 2b f8 8b cf c1 e1 90 01 01 03 4d 90 01 01 8b c7 c1 e8 90 01 01 03 45 90 01 01 03 f7 33 ce 33 c8 c7 05 90 02 08 c7 05 90 01 08 89 45 90 01 01 2b d9 8b 45 90 01 01 29 45 90 02 05 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}