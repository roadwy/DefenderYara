
rule TrojanDropper_Win32_Proscks_C{
	meta:
		description = "TrojanDropper:Win32/Proscks.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 04 01 00 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff e8 01 02 03 ff 15 ?? ?? ?? 00 68 ?? ?? ?? 00 e8 ?? ?? ff ff e8 01 02 03 ff 15 ?? ?? 40 00 e8 ?? ?? ff ff e8 01 02 03 e8 0c 00 00 00 74 61 73 6b 6d 67 72 2e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}