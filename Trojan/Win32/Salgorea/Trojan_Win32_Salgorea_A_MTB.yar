
rule Trojan_Win32_Salgorea_A_MTB{
	meta:
		description = "Trojan:Win32/Salgorea.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 9e 05 81 c7 45 ?? 4f 91 31 af c7 45 ?? cf a0 8f dc c7 45 ?? 53 69 47 38 c7 45 ?? f3 c8 bd b6 } //3
		$a_02_1 = {01 23 45 67 c7 85 ?? ?? ?? ?? 89 ab cd ef c7 85 ?? ?? ?? ?? fe dc ba 98 } //1
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*1) >=4
 
}