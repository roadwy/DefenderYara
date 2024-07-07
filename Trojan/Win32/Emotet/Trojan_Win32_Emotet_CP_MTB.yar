
rule Trojan_Win32_Emotet_CP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 00 00 00 47 81 e7 ff 00 00 00 0f b6 54 3c 90 01 01 03 ea 81 e5 ff 00 00 00 0f b6 44 2c 90 01 01 88 44 3c 90 01 01 02 c2 88 54 2c 90 01 01 0f b6 d0 8a 54 14 90 01 01 8b 44 24 0c 30 14 08 41 3b ce 7c 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_CP_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.CP!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 3c 8b 6c 24 20 03 d6 8a 04 02 30 45 00 ff 44 24 10 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}