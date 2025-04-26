
rule Trojan_Win32_Vidar_DAR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 0c 10 0f b6 55 fd 8b 45 f8 8a 4d ff 88 0c 10 0f b6 55 fe 8b 45 f8 0f b6 0c 10 0f b6 55 fd 8b 45 f8 0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c 08 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}