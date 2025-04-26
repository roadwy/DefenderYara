
rule Trojan_Win32_Tibs_GB{
	meta:
		description = "Trojan:Win32/Tibs.GB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 0c 8b 4d 08 89 11 03 7d 10 03 75 10 c9 [0-40] 8b 3b 89 e3 53 ff d7 [0-20] 96 58 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}