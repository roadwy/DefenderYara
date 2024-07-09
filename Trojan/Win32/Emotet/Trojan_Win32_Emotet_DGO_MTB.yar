
rule Trojan_Win32_Emotet_DGO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DGO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 18 83 c5 01 0f b6 94 14 ?? ?? ?? ?? 32 54 24 13 88 55 ff } //1
		$a_81_1 = {58 37 7b 79 49 58 33 46 71 4d 49 43 65 68 66 32 25 77 30 63 52 45 69 61 61 4b 5a 42 4d 4b 47 62 41 77 36 7a 69 75 40 67 72 71 68 } //1 X7{yIX3FqMICehf2%w0cREiaaKZBMKGbAw6ziu@grqh
		$a_81_2 = {71 42 51 65 38 33 53 4c 48 78 7c 7e 67 54 6c 45 73 6c 59 7a 7e 42 75 63 24 52 34 52 32 45 44 71 4d 7a 54 7c 68 } //1 qBQe83SLHx|~gTlEslYz~Buc$R4R2EDqMzT|h
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}