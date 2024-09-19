
rule Trojan_Win32_ValleyRAT_EC_MTB{
	meta:
		description = "Trojan:Win32/ValleyRAT.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 83 e0 0f 8a 04 08 30 04 16 46 3b f3 72 f0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}