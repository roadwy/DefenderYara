
rule Trojan_Win32_Redline_MII_MTB{
	meta:
		description = "Trojan:Win32/Redline.MII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 4d 0c 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 51 8d 45 ?? 50 e8 } //1
		$a_03_1 = {55 8b ec 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}