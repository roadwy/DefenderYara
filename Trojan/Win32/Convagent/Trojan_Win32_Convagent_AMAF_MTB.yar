
rule Trojan_Win32_Convagent_AMAF_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 8b 45 0c 50 0f b6 4d 08 51 e8 90 01 04 83 c4 08 8b f0 8b 55 0c 52 0f b6 45 08 50 e8 90 01 04 83 c4 08 25 00 00 00 f0 c1 e8 17 33 c6 5e 5d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}