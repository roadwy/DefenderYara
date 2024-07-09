
rule TrojanDownloader_Win32_Chepvil_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Chepvil.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {f2 af 8a 07 47 8b 0f 83 c7 04 57 51 6a 00 50 51 57 e8 ?? ?? 00 00 59 5f 90 09 0e 00 [0-02] 34 cc (68 ?? ?? ?? ??|5f bf ?? ?? ??) ?? b9 } //1
		$a_02_1 = {58 34 cc 68 ?? ?? ?? ?? 5f (68|b9) ?? ?? ?? ?? [0-01] f2 af [0-05] 8a 07 47 8b 0f 83 c7 04 57 51 6a 00 50 51 57 90 03 06 09 e8 ?? ?? 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? c3 59 5f } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}