
rule Trojan_Win32_CobaltStrike_CCDE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.CCDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 83 c5 03 55 53 ff 15 } //1
		$a_03_1 = {88 0e 0f b6 50 ?? 0f b6 54 94 ?? 0f b6 48 ?? c0 e2 ?? 0a 54 8c ?? 83 c6 ?? 88 56 fe 83 c0 ?? 83 ef ?? 75 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}