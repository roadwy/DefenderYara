
rule TrojanSpy_Win32_Obfuscator_KG_MTB{
	meta:
		description = "TrojanSpy:Win32/Obfuscator.KG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 bd 78 ff ff ff 89 95 6c ff ff ff 8b 55 88 03 55 94 0f be 02 8b 8d 6c ff ff ff 0f be 54 0d 98 33 c2 8b 4d 88 03 4d 94 88 01 eb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}