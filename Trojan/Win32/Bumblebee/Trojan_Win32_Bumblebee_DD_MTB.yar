
rule Trojan_Win32_Bumblebee_DD_MTB{
	meta:
		description = "Trojan:Win32/Bumblebee.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 8b 4d bc 0f b7 14 41 8b 45 b8 8b 4d 0c 03 0c 90 89 4d e4 8b 55 f8 8b 45 bc 0f b7 0c 50 8b 55 b8 8b 45 08 03 04 8a 89 45 a8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}