
rule Trojan_Win32_Redline_MJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f 90 01 01 80 07 90 01 01 f6 2f 47 e2 f3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}