
rule Trojan_Win32_Makplu_A{
	meta:
		description = "Trojan:Win32/Makplu.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {75 f7 2b ca 51 56 8d 4c 24 90 01 01 e8 90 01 02 ff ff 6a 01 68 90 01 04 8d 4c 24 90 01 01 e8 90 01 02 ff ff a1 90 01 04 83 f8 90 01 01 77 90 01 01 ff 24 85 90 01 04 68 90 01 04 eb 90 01 01 68 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}