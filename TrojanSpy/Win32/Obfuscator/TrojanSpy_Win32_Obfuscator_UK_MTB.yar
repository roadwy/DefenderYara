
rule TrojanSpy_Win32_Obfuscator_UK_MTB{
	meta:
		description = "TrojanSpy:Win32/Obfuscator.UK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 33 c9 c7 45 ?? ?? ?? ?? ?? 85 f6 74 1b 8a 81 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 83 f9 ?? [0-02] 33 c9 [0-02] 41 42 3b d6 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}