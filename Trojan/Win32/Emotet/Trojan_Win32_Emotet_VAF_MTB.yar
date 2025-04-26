
rule Trojan_Win32_Emotet_VAF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c8 89 4d a8 31 c9 89 55 ?? 89 ca f7 f7 8b 4d d0 81 f6 11 ac 52 09 8b 7d a4 81 f7 10 ac 52 09 89 4d a0 8b 4d a8 21 f9 8b 7d a0 89 4d 9c } //5
		$a_03_1 = {8b 45 e4 8b 4d f4 81 f1 2c 25 d7 3e 8b 55 ec 8a 1c 02 8b 75 e8 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 e4 74 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}