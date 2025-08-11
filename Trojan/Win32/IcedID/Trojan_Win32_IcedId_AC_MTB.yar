
rule Trojan_Win32_IcedId_AC_MTB{
	meta:
		description = "Trojan:Win32/IcedId.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b dc e6 e8 00 68 45 58 82 72 5a 00 00 22 10 f8 d8 48 02 b2 00 68 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}