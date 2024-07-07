
rule Trojan_Win32_Emotet_DAG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAG!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 f2 81 e6 ff 00 00 00 8b 5c b0 08 89 5c 88 08 89 54 b0 08 03 da 81 e3 ff 00 00 00 0f b6 54 98 08 32 55 00 83 c1 01 88 17 } //1
		$a_01_1 = {c1 c8 0d 80 f9 61 0f b6 c9 72 03 83 e9 20 83 c2 01 03 c1 8a 0a 84 c9 75 e7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}