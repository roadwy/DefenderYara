
rule Trojan_Win32_DanaBot_GC_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 65 ?? 8b 45 ?? 81 45 [0-30] 81 ad [0-30] 81 45 [0-20] 8b 85 ?? ?? ?? ?? 30 0c 30 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}