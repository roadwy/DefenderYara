
rule Trojan_Win32_Redline_GSM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 33 7d 90 01 01 31 7d 90 01 01 83 3d 90 01 05 75 90 00 } //1
		$a_03_1 = {d3 e0 03 45 90 01 01 33 45 90 01 01 33 c2 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8d 45 90 01 01 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}