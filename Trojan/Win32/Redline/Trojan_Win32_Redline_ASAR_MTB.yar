
rule Trojan_Win32_Redline_ASAR_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f b6 02 35 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 68 } //1
		$a_03_1 = {8b 55 08 03 55 fc 0f b6 02 05 ?? 00 00 00 8b 4d 08 03 4d fc 88 01 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}