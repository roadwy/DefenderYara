
rule Trojan_Win32_Redline_DAP_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 07 29 80 2f 44 47 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}