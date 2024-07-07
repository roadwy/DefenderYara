
rule Trojan_Win32_Redline_MII_MTB{
	meta:
		description = "Trojan:Win32/Redline.MII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 4d 0c 89 35 90 01 04 33 4d 90 01 01 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 51 8d 45 90 01 01 50 e8 90 00 } //1
		$a_03_1 = {55 8b ec 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}