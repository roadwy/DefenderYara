
rule Trojan_Win32_Lazy_SQDB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.SQDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {56 7a 68 68 6f 61 65 45 6e 77 73 61 73 69 6f } //2 VzhhoaeEnwsasio
		$a_01_1 = {6c 68 6e 77 6b 74 70 38 30 2e 64 6c 6c } //1 lhnwktp80.dll
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}