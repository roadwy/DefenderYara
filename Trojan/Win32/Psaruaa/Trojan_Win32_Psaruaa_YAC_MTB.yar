
rule Trojan_Win32_Psaruaa_YAC_MTB{
	meta:
		description = "Trojan:Win32/Psaruaa.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 b5 bc 9a ff ff 0f b6 92 00 00 42 00 33 ca 8b 85 ec ?? ff ff 88 8c 05 f8 d6 ff ff eb b3 } //10
		$a_03_1 = {0f b6 92 00 00 42 00 33 ca 8b 85 b8 ?? ff ff 03 85 e8 9a ff ff 88 08 } //6
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*6) >=16
 
}