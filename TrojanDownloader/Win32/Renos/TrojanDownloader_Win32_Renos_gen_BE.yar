
rule TrojanDownloader_Win32_Renos_gen_BE{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 18 88 11 8a ca 02 08 0f b6 c1 8a 84 05 ?? ?? ff ff 32 04 37 88 06 46 ff 4d 08 75 b0 } //1
		$a_03_1 = {74 14 8d 45 ?? 50 e8 ?? ?? 00 00 59 89 7d ?? 59 c6 45 ?? 03 eb 19 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}