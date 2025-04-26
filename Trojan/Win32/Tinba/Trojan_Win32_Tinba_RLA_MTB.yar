
rule Trojan_Win32_Tinba_RLA_MTB{
	meta:
		description = "Trojan:Win32/Tinba.RLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 4d e8 8a 75 cb 80 c6 4f 88 75 cb 88 10 8b 45 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}