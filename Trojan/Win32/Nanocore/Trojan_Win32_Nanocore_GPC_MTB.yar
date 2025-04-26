
rule Trojan_Win32_Nanocore_GPC_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8f e2 96 70 a3 b3 35 9f 8f e2 96 70 a3 b3 35 9f 41 55 33 21 45 41 30 36 4d a8 ff 73 24 a7 3c f6 7a 12 f1 67 ac c1 93 e7 6b 43 ca 52 a6 ad } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}