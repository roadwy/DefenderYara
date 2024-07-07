
rule Trojan_Win32_Tinba_CC_MTB{
	meta:
		description = "Trojan:Win32/Tinba.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 b0 03 55 a8 2b 55 b0 8b 45 b0 03 c2 89 45 b0 8b 4d 84 81 e9 f0 00 00 00 8b 55 84 2b d1 89 55 84 e9 } //1
		$a_01_1 = {2b c8 89 4d c0 8b 55 84 03 55 90 8b 45 b0 8d 8c 10 bd 01 00 00 89 4d b0 8b 55 bc 2b 55 84 8b 45 90 2b c2 89 45 90 8b 4d bc 69 c9 4d fe ff ff 81 c1 e4 03 00 00 89 4d b0 c7 45 fc ff ff ff ff eb 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}