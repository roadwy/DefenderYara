
rule Trojan_Win32_Vidar_GFA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 8d 64 24 00 68 90 01 04 68 90 01 04 ff d7 a1 90 01 04 80 34 30 90 01 01 46 3b 35 90 01 04 72 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}