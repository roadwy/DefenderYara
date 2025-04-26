
rule TrojanDropper_BAT_Eterock_A{
	meta:
		description = "TrojanDropper:BAT/Eterock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 78 70 6c 6f 69 74 73 00 6f 73 56 65 72 73 69 6f 6e } //1 硥汰楯獴漀噳牥楳湯
		$a_01_1 = {57 49 4e 38 5f 53 50 30 00 53 45 52 56 45 52 5f 32 4b 31 32 5f 53 50 30 } //1 䥗㡎卟ぐ匀剅䕖归䬲㈱卟ぐ
		$a_01_2 = {52 75 6e 4f 6e 6c 79 49 66 4c 6f 67 67 65 64 4f 6e } //1 RunOnlyIfLoggedOn
		$a_01_3 = {2e 73 68 61 64 6f 77 62 72 6f 6b 65 72 73 2e 7a 69 70 } //1 .shadowbrokers.zip
		$a_01_4 = {45 74 65 72 6e 61 6c 52 6f 63 6b 73 2e 65 78 65 } //1 EternalRocks.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}