
rule Trojan_Win32_Vidar_SPRD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SPRD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 6c 24 0c 64 8a 4c 24 0c 30 0c 33 83 ff 0f 75 90 01 01 8b 54 24 08 8b 4c 24 08 55 55 52 8d 44 24 38 50 51 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}