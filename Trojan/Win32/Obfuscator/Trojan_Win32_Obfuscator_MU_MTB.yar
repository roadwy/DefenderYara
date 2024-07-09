
rule Trojan_Win32_Obfuscator_MU_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 33 0d ?? ?? ?? ?? 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 } //1
		$a_02_1 = {55 8b ec 51 8b [0-02] 89 [0-02] 8b [0-05] 89 [0-02] 8b [0-02] f7 da 8b [0-02] 8b 08 2b ca 8b 55 08 89 0a 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}