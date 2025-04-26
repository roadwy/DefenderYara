
rule Trojan_Win32_Redline_NYK_MTB{
	meta:
		description = "Trojan:Win32/Redline.NYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 8b 4d ?? 89 45 ?? 8b c3 03 55 ?? d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 33 55 ?? 8d 4d ?? 52 ff 75 ?? 89 55 ?? e8 } //1
		$a_01_1 = {8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}