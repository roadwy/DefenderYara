
rule Trojan_Win32_Enchanim_A{
	meta:
		description = "Trojan:Win32/Enchanim.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 38 06 00 01 40 74 ?? 8b 40 0c 80 38 f8 74 ?? 80 38 e4 74 ?? 80 38 ec 0f 84 ?? ?? ?? ?? 80 38 ed 0f 84 } //1
		$a_03_1 = {81 38 06 00 01 40 74 ?? 8b 50 0c 80 3a f8 74 ?? 80 3a e4 74 ?? 80 3a ec 0f 84 ?? ?? ?? ?? 80 3a ed 0f 84 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}