
rule Trojan_Win32_Guloader_SMTF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SMTF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f4 03 45 f8 88 10 8b 45 e0 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 e0 eb a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}