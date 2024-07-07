
rule Trojan_Win32_Cerber_MR_MTB{
	meta:
		description = "Trojan:Win32/Cerber.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 f1 56 88 88 02 30 41 00 8a 88 03 30 41 00 84 c9 74 0e 80 f9 56 74 09 80 f1 56 88 88 03 30 41 00 8a 88 04 30 41 00 84 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}