
rule Trojan_Win32_MewsSpy_CCJT_MTB{
	meta:
		description = "Trojan:Win32/MewsSpy.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 56 04 8a 14 0a 32 56 fc 41 88 54 01 ff 3b 0e 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}