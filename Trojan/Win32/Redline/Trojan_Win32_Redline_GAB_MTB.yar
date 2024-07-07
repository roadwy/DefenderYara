
rule Trojan_Win32_Redline_GAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 a3 90 01 04 8b 95 90 01 04 a1 90 01 04 03 c2 80 30 90 01 01 8d 8d 90 01 04 51 ff d6 01 3d 90 01 04 8b 15 90 01 04 74 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}