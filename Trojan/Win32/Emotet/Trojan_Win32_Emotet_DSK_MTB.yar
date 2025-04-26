
rule Trojan_Win32_Emotet_DSK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a bc 04 60 01 00 00 88 bc 0c 60 01 00 00 88 9c 04 60 01 00 00 42 89 8c 24 98 02 00 00 8b 8c 24 cc 00 00 00 81 c1 f5 10 ac b9 8b b4 24 c8 00 00 00 83 d6 ff 89 8c 24 b0 02 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}