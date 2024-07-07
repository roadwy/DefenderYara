
rule Trojan_Win32_Zenpak_PVS_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 44 0a c5 88 45 f3 0f b7 0d 90 01 04 69 c9 be 00 01 00 0f b6 55 f3 0f af ca 88 4d f3 0f b6 05 90 01 04 3d 76 14 00 00 75 90 09 06 00 8b 15 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}