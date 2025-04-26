
rule Trojan_Win32_FormBook_AR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 06 46 84 c0 75 ?? 2b f2 8d a4 24 00 00 00 00 8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 3b cf 72 } //2
		$a_03_1 = {8b c1 33 d2 f7 f6 41 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 3b cf 72 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}