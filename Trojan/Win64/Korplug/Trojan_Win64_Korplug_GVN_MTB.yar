
rule Trojan_Win64_Korplug_GVN_MTB{
	meta:
		description = "Trojan:Win64/Korplug.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f af c2 83 e0 01 83 f8 00 0f 94 c0 83 f9 0a 0f 9c c1 88 c2 20 ca 30 c8 08 c2 b8 89 cf 75 d8 b9 90 f7 6a cd f6 c2 01 0f 45 c1 89 45 ac e9 e1 03 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}