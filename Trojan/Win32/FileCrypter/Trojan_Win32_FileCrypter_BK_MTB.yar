
rule Trojan_Win32_FileCrypter_BK_MTB{
	meta:
		description = "Trojan:Win32/FileCrypter.BK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e0 04 89 01 c3 cc cc cc cc cc cc cc cc cc cc 31 08 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}