
rule Trojan_Win32_Vidar_PH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 8b d7 d3 e2 8b 4d 90 01 01 89 45 90 01 01 8b c7 03 55 d4 d3 e8 89 45 f8 8b 45 d0 01 45 f8 33 55 ec 8d 4d e0 52 ff 75 f8 89 55 e0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}