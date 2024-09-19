
rule Trojan_Win32_Tinba_MKV_MTB{
	meta:
		description = "Trojan:Win32/Tinba.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b c8 03 4d dc 8b 55 f0 03 d1 89 55 f0 8b 45 d8 0f af 45 b4 03 45 cc 8a 4d d0 02 c8 88 4d d0 8b 55 b8 83 c2 02 89 55 b8 8b 45 b8 33 c9 66 8b 08 85 c9 0f 85 f0 fe ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}