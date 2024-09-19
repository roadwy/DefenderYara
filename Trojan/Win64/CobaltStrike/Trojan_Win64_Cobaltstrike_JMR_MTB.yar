
rule Trojan_Win64_Cobaltstrike_JMR_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.JMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {99 f7 fb 48 63 c2 0f b6 84 87 59 04 00 00 89 ca c1 ea 08 42 32 14 08 88 54 ae 02 48 8b 44 24 28 01 e8 99 f7 fb 48 63 c2 0f b6 84 87 58 04 00 00 42 32 0c 08 88 4c ae 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}