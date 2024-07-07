
rule Trojan_Win32_Redline_LSF_MTB{
	meta:
		description = "Trojan:Win32/Redline.LSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 c1 e8 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 83 25 90 01 05 c1 e1 90 01 01 03 cf 33 4d 90 01 01 8d 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}