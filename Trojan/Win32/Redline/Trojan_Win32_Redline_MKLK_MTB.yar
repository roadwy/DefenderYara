
rule Trojan_Win32_Redline_MKLK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MKLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 83 25 90 01 05 8d 14 01 8b c8 c1 e1 90 01 01 03 4d 90 01 01 c1 e8 90 01 01 33 ca 03 c3 33 c1 89 55 0c 90 00 } //1
		$a_03_1 = {01 45 fc 83 6d fc 90 01 01 8b 45 90 01 01 8b 4d 90 01 01 31 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}