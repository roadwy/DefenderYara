
rule Trojan_Win64_Emotetcrypt_KU_MTB{
	meta:
		description = "Trojan:Win64/Emotetcrypt.KU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {4d 8d 40 01 f7 e7 8b cf 4d 8d 49 01 c1 ea ?? ff c7 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 10 41 32 49 ff 41 88 48 ff 41 3b fb 7d 09 4c 8b 15 ?? ?? ?? ?? eb } //1
		$a_01_1 = {23 6a 67 44 25 53 41 6e 53 73 46 49 71 63 79 52 79 6d 6f 5e 68 2a 2b 23 23 36 51 46 52 37 6f 74 44 25 3e 6b 69 54 36 50 76 5a 73 67 6c 58 79 67 77 25 3e 63 4c 75 5a 28 31 3c 40 4d 2a 67 } //1 #jgD%SAnSsFIqcyRymo^h*+##6QFR7otD%>kiT6PvZsglXygw%>cLuZ(1<@M*g
		$a_01_2 = {62 64 58 5a 4c 28 6a 43 58 32 34 3f 6e 24 5a 76 57 6d 66 59 5a 6d 75 68 79 3e 37 3f 30 46 66 32 49 28 4c 23 3f 26 68 5a 29 52 58 3e 6c 4f 35 38 57 77 4c 4d 52 48 24 4a 52 35 25 39 6f 5a } //1 bdXZL(jCX24?n$ZvWmfYZmuhy>7?0Ff2I(L#?&hZ)RX>lO58WwLMRH$JR5%9oZ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}