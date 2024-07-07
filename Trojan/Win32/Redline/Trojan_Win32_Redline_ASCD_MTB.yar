
rule Trojan_Win32_Redline_ASCD_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 15 90 01 02 ff ff 8b 4d 08 03 8d 90 01 02 ff ff 0f b6 11 33 d0 8b 45 08 03 85 90 01 02 ff ff 88 10 e9 90 00 } //4
		$a_01_1 = {6a 40 68 00 10 00 00 68 ac 04 00 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}