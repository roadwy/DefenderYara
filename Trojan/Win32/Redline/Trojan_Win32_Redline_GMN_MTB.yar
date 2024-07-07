
rule Trojan_Win32_Redline_GMN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 8d 44 24 20 55 50 e8 90 01 04 69 4c 24 90 01 01 91 e9 d1 5b 83 c4 0c 69 db 91 e9 d1 5b 83 c5 04 8b c1 c1 e8 18 33 c1 69 c0 91 e9 d1 5b 33 d8 89 44 24 1c 83 ee 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}