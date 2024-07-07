
rule Trojan_Win32_Dridex_RR_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 44 24 3c 2d 65 73 2d c7 44 24 40 2d 70 70 2d c7 44 24 44 2d 2d 2d 00 88 c2 80 c2 5b 34 7c 88 4c 24 3c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}