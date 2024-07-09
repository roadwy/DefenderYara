
rule TrojanDownloader_Win32_Zlob_gen_ANQ{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!ANQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {60 9c fc e8 00 00 00 00 5f 81 ef ?? ?? ?? ?? 8b c7 81 c7 ?? ?? ?? ?? 3b 47 2c 75 02 eb 36 89 47 2c b9 a8 00 00 00 eb 0d } //1
		$a_01_1 = {6c 75 62 72 69 63 2e 64 6c 6c 00 63 61 6e 74 6f 00 6d 75 74 6f 62 72 6f 6e 63 00 70 65 79 64 65 79 72 61 00 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}