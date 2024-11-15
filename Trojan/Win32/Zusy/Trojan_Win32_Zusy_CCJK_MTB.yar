
rule Trojan_Win32_Zusy_CCJK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CCJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 6a ff 68 f8 d4 65 00 68 08 64 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 a0 d2 65 00 33 d2 8a d4 89 15 ac 5d a6 00 8b c8 81 e1 ff 00 00 00 89 0d a8 5d a6 00 c1 e1 08 03 ca 89 0d a4 5d a6 00 c1 e8 10 a3 a0 5d a6 00 6a 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}