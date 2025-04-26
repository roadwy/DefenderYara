
rule TrojanDownloader_Win32_Banload_KV{
	meta:
		description = "TrojanDownloader:Win32/Banload.KV,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 45 59 3a 06 28 68 74 74 70 3a 2f 2f 77 77 77 2e 76 65 72 63 61 72 74 61 6f 2e 63 6f 6d 2f 49 6e 73 74 61 6c 6c 2f 25 41 30 2e 64 6c 6c 06 14 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 68 6f 6f 74 2e 64 6c 6c 06 04 57 41 42 3a } //1 䕋㩙⠆瑨灴⼺眯睷瘮牥慣瑲潡挮浯䤯獮慴汬┯ぁ搮汬ᐆ㩃坜湩潤獷卜潨瑯搮汬І䅗㩂
		$a_01_1 = {72 75 6e 64 6c 6c 33 32 20 53 68 6f 6f 74 2e 64 6c 6c 2c 6e 65 74 77 6f 72 6b 00 00 07 54 49 64 48 54 54 50 0e 6f 70 65 6e 5f 79 6f 75 72 5f 6d 69 6e 64 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}