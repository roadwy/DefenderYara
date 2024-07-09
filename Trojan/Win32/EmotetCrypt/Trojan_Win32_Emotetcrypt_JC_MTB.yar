
rule Trojan_Win32_Emotetcrypt_JC_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.JC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ea 0f af e9 2b dd 2b d8 2b d8 2b d8 2b d8 8b 44 24 ?? 2b de 2b d9 2b d9 2b d9 2b d9 03 df 03 df 8a 0c 03 8b 44 24 ?? 8a 18 32 d9 8b 4c 24 ?? 88 18 } //1
		$a_01_1 = {66 46 34 62 6f 41 41 71 33 78 6d 51 41 69 51 21 41 63 38 26 36 65 51 45 69 34 21 6e 49 51 28 32 69 68 51 5e 3c 73 43 4b 30 25 74 5f 62 4a 2a 48 3f 76 47 } //1 fF4boAAq3xmQAiQ!Ac8&6eQEi4!nIQ(2ihQ^<sCK0%t_bJ*H?vG
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}