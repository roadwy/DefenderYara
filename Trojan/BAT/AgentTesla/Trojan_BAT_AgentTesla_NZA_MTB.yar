
rule Trojan_BAT_AgentTesla_NZA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 bb 0f 00 00 95 7e 90 01 03 04 19 9a 20 28 0f 00 00 95 11 04 61 7e 1d 00 00 04 19 9a 20 ce 0d 00 00 95 59 7e 1d 00 00 04 1a 9a 19 95 61 7e 1d 00 00 04 19 9a 20 7d 04 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NZA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {24 62 36 35 34 65 65 62 33 2d 31 62 66 32 2d 34 30 62 38 2d 39 33 66 66 2d 35 32 36 36 65 37 63 34 32 36 30 30 } //10 $b654eeb3-1bf2-40b8-93ff-5266e7c42600
		$a_01_1 = {24 61 30 30 63 32 66 64 61 2d 62 34 62 39 2d 34 34 62 31 2d 61 63 36 31 2d 35 62 62 39 63 39 38 34 37 61 65 30 } //10 $a00c2fda-b4b9-44b1-ac61-5bb9c9847ae0
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {43 72 79 70 74 6f 53 74 72 65 61 6d } //1 CryptoStream
		$a_01_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_5 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_6 = {54 72 61 6e 73 66 6f 72 6d 42 6c 6f 63 6b } //1 TransformBlock
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}