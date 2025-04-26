
rule Trojan_Win32_Redline_CCBE_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b de 33 f6 33 de 80 2f ?? 33 f6 33 d8 33 f3 80 07 ?? 33 f3 33 f0 33 c6 f6 2f 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}