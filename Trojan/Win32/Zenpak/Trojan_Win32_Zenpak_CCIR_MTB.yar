
rule Trojan_Win32_Zenpak_CCIR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 06 00 00 00 83 f2 09 83 f2 06 8d 05 ?? ?? ?? ?? c7 00 00 00 00 00 01 20 b9 02 00 00 00 e2 1c ba 06 00 00 00 83 c2 03 31 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}