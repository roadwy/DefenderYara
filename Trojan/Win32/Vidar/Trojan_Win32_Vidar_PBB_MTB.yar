
rule Trojan_Win32_Vidar_PBB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 4d 90 01 01 83 0d 90 01 05 8b c6 c1 e8 05 03 c3 03 ce 33 c8 31 4d 08 c7 05 90 01 08 89 45 0c 8b 45 08 29 45 f8 8b 45 e4 29 45 fc ff 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}