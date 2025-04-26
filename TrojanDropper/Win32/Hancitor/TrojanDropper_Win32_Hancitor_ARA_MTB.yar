
rule TrojanDropper_Win32_Hancitor_ARA_MTB{
	meta:
		description = "TrojanDropper:Win32/Hancitor.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8d 14 80 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0e 41 3b 0d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}