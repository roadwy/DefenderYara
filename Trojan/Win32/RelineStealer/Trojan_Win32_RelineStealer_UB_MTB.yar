
rule Trojan_Win32_RelineStealer_UB_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.UB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 31 83 ff ?? 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}