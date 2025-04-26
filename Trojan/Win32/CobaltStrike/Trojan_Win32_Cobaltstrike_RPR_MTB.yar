
rule Trojan_Win32_Cobaltstrike_RPR_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 8d 76 00 0f b6 04 0a 88 04 1a 42 84 c0 75 f4 8b 35 28 80 40 00 85 f6 87 d0 c1 c9 03 33 c7 c1 cb 17 2b d4 03 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}