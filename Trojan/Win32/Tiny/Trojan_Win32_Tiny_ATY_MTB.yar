
rule Trojan_Win32_Tiny_ATY_MTB{
	meta:
		description = "Trojan:Win32/Tiny.ATY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 6a 00 6a 06 6a 01 6a 02 ff 15 10 31 01 10 a3 10 b4 01 10 68 00 a0 01 10 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}