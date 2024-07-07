
rule Trojan_Win32_Convagent_EC_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f be 04 10 6b c0 31 99 b9 24 00 00 00 f7 f9 83 e0 02 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}