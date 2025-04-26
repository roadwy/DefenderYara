
rule Trojan_Win32_Redline_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 04 2f ?? ff d6 80 34 2f ?? ff d6 80 04 2f } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}