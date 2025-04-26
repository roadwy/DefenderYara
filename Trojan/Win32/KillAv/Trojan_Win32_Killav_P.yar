
rule Trojan_Win32_Killav_P{
	meta:
		description = "Trojan:Win32/Killav.P,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 51 50 50 50 50 68 04 80 22 00 ff 75 f8 ff 15 ?? ?? ?? ?? 60 b8 01 00 00 00 61 ff ?? ?? e8 ?? ?? ?? ?? 59 50 6a 00 6a 01 ff 15 ?? ?? ?? ?? 6a 00 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}