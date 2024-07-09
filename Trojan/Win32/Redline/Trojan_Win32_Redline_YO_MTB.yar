
rule Trojan_Win32_Redline_YO_MTB{
	meta:
		description = "Trojan:Win32/Redline.YO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 } //1
		$a_03_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 33 55 ?? 8d 4d ?? 52 ff 75 ?? 89 55 ?? e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}