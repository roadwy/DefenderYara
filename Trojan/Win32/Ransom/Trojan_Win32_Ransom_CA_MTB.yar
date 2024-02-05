
rule Trojan_Win32_Ransom_CA_MTB{
	meta:
		description = "Trojan:Win32/Ransom.CA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 04 f5 b4 65 40 00 0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 f5 b0 65 40 00 66 33 c8 47 66 89 0c 53 66 3b 3c f5 b2 65 40 00 72 cc } //01 00 
		$a_01_1 = {fe c3 0f b6 f3 8a 14 3e 02 fa 0f b6 cf 8a 04 39 88 04 3e 88 14 39 0f b6 0c 3e 0f b6 c2 03 c8 81 e1 ff 00 00 00 8a 04 39 8b 4c 24 10 30 04 29 45 3b 6c 24 14 72 ca } //00 00 
	condition:
		any of ($a_*)
 
}