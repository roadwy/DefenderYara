
rule Trojan_Win32_FormBook_DE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 45 ff 88 45 ?? 8a 45 ?? 34 ?? 88 45 ?? 03 11 [0-30] 8a 45 ?? 88 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}