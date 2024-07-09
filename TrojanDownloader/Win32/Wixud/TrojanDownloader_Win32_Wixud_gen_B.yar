
rule TrojanDownloader_Win32_Wixud_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Wixud.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {74 07 6a 00 e8 ?? ?? 00 00 bf ?? ?? 40 00 b9 ?? ?? ?? ?? a1 ?? ?? 40 00 01 44 8f fc e2 f5 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}