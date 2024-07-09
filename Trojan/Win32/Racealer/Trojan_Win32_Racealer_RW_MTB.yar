
rule Trojan_Win32_Racealer_RW_MTB{
	meta:
		description = "Trojan:Win32/Racealer.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 56 57 33 f6 33 ff 39 75 ?? 7e ?? e8 ?? ?? ?? ?? 30 04 3b 83 7d ?? 19 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}