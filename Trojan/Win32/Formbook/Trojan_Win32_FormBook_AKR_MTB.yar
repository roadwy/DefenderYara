
rule Trojan_Win32_FormBook_AKR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AKR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 04 04 34 8a 04 74 34 be 04 30 34 9b 2c 67 34 3d 88 04 3b 47 3b 7d fc 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}