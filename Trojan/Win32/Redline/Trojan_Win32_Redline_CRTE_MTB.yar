
rule Trojan_Win32_Redline_CRTE_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRTE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 2f 90 01 01 80 2f 90 01 01 47 e2 f5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}