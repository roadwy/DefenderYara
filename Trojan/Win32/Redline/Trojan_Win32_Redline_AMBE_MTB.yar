
rule Trojan_Win32_Redline_AMBE_MTB{
	meta:
		description = "Trojan:Win32/Redline.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e8 8b 7d 90 02 15 f6 17 90 02 19 80 07 90 02 0f 80 2f 90 02 15 f6 2f 47 e2 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}