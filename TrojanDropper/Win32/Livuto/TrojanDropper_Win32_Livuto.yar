
rule TrojanDropper_Win32_Livuto{
	meta:
		description = "TrojanDropper:Win32/Livuto,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 13 99 59 f7 f9 8b 45 ?? 80 c2 61 88 14 06 46 83 fe 0b 7c } //1
		$a_03_1 = {80 c9 ff 2a 08 47 81 ff ?? ?? ?? ?? 88 08 72 ea } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}