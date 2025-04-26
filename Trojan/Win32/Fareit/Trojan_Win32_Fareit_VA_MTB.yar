
rule Trojan_Win32_Fareit_VA_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 4c 24 04 30 01 } //1
		$a_02_1 = {8b 4c 24 08 0f af c8 89 0c 24 c7 44 24 04 ?? ?? ?? ?? 81 44 24 04 ?? ?? ?? ?? 8b 44 24 04 01 04 24 8b 04 24 a3 ?? ?? ?? ?? c1 e8 ?? 25 ?? ?? ?? ?? 83 c4 ?? c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}