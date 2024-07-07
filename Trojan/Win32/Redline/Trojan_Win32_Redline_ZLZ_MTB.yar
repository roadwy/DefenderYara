
rule Trojan_Win32_Redline_ZLZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ZLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 cb 33 4d 08 8d 45 90 01 01 33 4d 90 01 01 51 50 89 4d 90 01 01 e8 90 00 } //1
		$a_03_1 = {c1 e0 04 03 c7 33 45 08 33 45 90 01 01 50 8d 45 90 01 01 50 e8 90 01 04 83 65 fc 00 8b 45 90 01 01 01 45 90 01 01 2b 55 90 01 01 ff 4d 90 01 01 89 55 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}