
rule Trojan_Win32_Redline_QM_MTB{
	meta:
		description = "Trojan:Win32/Redline.QM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c1 8b 0d 18 5a 43 00 88 81 20 5a 43 00 8b 15 18 5a 43 00 0f b6 82 20 5a 43 00 89 45 bc a1 4c b8 42 00 0f b6 88 20 5a 43 00 33 4d bc 8b 15 4c b8 42 00 88 8a 20 5a 43 00 a1 4c b8 42 00 0f b6 88 20 5a 43 00 8b 15 18 5a 43 00 0f b6 82 20 5a 43 00 33 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}