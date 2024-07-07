
rule Trojan_Win32_DanaBot_GC_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b8 b7 59 e7 1f f7 65 90 01 01 8b 45 90 01 01 81 45 90 02 30 81 ad 90 02 30 81 45 90 02 20 8b 85 90 01 04 30 0c 30 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}