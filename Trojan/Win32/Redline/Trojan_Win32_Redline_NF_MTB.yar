
rule Trojan_Win32_Redline_NF_MTB{
	meta:
		description = "Trojan:Win32/Redline.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 3b c3 76 09 80 34 11 90 01 01 42 3b d0 72 f7 8d 55 bc 52 90 0a 29 00 a1 90 01 04 8b 0d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}