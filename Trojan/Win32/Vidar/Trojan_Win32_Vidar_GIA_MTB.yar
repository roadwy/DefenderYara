
rule Trojan_Win32_Vidar_GIA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 08 8b c6 83 e0 03 46 83 c4 0c 8a 04 08 30 07 8b 45 f8 3b 75 fc } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}