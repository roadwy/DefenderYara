
rule TrojanSpy_Win32_Obfuscator_UK_MTB{
	meta:
		description = "TrojanSpy:Win32/Obfuscator.UK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 33 c9 c7 45 90 01 05 85 f6 74 1b 8a 81 90 01 04 30 82 90 01 04 83 f9 90 01 01 90 02 02 33 c9 90 02 02 41 42 3b d6 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}