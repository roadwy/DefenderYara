
rule Trojan_Win32_FormBook_CO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 1c 0f f7 [0-40] 31 f3 [0-c8] 09 1c 0a } //5
		$a_00_1 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //1 MSVBVM60.DLL
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1) >=6
 
}