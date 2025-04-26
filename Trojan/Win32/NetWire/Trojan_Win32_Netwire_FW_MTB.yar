
rule Trojan_Win32_Netwire_FW_MTB{
	meta:
		description = "Trojan:Win32/Netwire.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {56 33 f6 85 ff 7e ?? 81 ff ?? ?? 00 00 75 ?? [0-04] ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 46 3b f7 7c ?? 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}