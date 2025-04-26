
rule Trojan_Win32_Redline_CRIT_MTB{
	meta:
		description = "Trojan:Win32/Redline.CRIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 17 80 2f a6 47 e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}