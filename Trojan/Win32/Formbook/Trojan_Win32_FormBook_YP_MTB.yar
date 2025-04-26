
rule Trojan_Win32_FormBook_YP_MTB{
	meta:
		description = "Trojan:Win32/FormBook.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {88 02 83 45 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 45 ?? 41 81 7d [0-10] 90 13 8a 01 34 ?? 88 45 ?? 8b 55 ?? 8a 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}