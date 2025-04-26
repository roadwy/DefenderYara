
rule Trojan_Win32_FormBook_AO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 01 88 45 ?? 8b 55 ?? 8a 45 ?? 88 02 b0 ?? 30 02 83 45 fc ?? 73 ?? e8 ?? ?? ?? ?? ff 45 ?? 41 81 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}