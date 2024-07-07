
rule Trojan_Win32_Zenpak_BU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 06 0f b6 fb 01 cf 89 45 d8 31 c9 89 55 d4 89 ca 8b 4d f0 f7 f1 8b 4d ec 0f b6 14 11 01 d7 89 f8 99 8b 7d d4 f7 ff 8a 3c 16 8b 4d d8 88 3c 0e 88 1c 16 81 c1 01 00 00 00 81 f9 00 01 00 00 89 55 e0 89 4d dc 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}