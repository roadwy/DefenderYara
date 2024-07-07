
rule Trojan_Win32_Glupteba_NS_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {75 08 50 50 ff 15 90 02 04 e8 90 02 04 30 90 02 03 33 90 02 03 3b 90 02 03 90 18 81 90 00 } //1
		$a_02_1 = {55 8b ec 51 51 56 33 f6 81 3d 90 02 08 90 18 a1 90 02 04 69 90 02 05 81 3d 90 02 08 90 02 08 a3 90 02 04 90 18 89 90 02 03 81 90 02 06 8b 90 02 03 01 90 02 05 0f 90 02 06 25 90 02 04 5e c9 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}