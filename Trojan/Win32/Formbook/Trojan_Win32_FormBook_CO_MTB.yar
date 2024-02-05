
rule Trojan_Win32_FormBook_CO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_02_0 = {8b 1c 0f f7 90 02 40 31 f3 90 02 c8 09 1c 0a 90 00 } //01 00 
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}