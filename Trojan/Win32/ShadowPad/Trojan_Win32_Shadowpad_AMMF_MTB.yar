
rule Trojan_Win32_Shadowpad_AMMF_MTB{
	meta:
		description = "Trojan:Win32/Shadowpad.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c1 88 02 8b c1 e8 ?? ?? ?? ?? 89 45 fc 8b c1 e8 ?? ?? ?? ?? 03 45 fc e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 42 [0-05] 8b c8 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}