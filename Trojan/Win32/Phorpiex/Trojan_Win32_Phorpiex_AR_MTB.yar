
rule Trojan_Win32_Phorpiex_AR_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 } //1
		$a_00_1 = {33 d8 8b 45 08 03 45 fc 88 18 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}