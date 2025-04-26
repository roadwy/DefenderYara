
rule Trojan_Win32_CobaltStrike_FK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 07 47 84 c0 75 } //1
		$a_03_1 = {8b c6 99 f7 ff 8a 44 15 ?? 32 84 35 ?? ?? ?? ?? 88 84 35 ?? ?? ?? ?? 0f b6 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}