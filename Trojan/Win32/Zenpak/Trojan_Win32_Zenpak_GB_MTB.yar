
rule Trojan_Win32_Zenpak_GB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 85 a8 fd ff ff 33 d2 b9 0a 00 00 00 f7 f1 b8 01 00 00 00 6b c8 00 8d 84 0d 70 ef ff ff 0f be 0c 10 8b 95 e0 f7 ff ff 03 95 a8 fd ff ff 0f b6 02 33 c1 8b 8d e0 f7 ff ff 03 8d a8 fd ff ff 88 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}