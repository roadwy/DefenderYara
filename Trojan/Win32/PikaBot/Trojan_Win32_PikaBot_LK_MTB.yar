
rule Trojan_Win32_PikaBot_LK_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 1c 01 8b 86 ?? ?? ?? 00 ff 86 ?? ?? ?? 00 48 31 05 ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f 8c ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}