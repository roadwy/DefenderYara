
rule Trojan_Win32_FormBook_P_MTB{
	meta:
		description = "Trojan:Win32/FormBook.P!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 03 d9 73 90 01 01 e8 90 01 04 80 33 e9 41 4a 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}