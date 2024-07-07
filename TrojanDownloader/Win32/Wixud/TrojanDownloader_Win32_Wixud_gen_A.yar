
rule TrojanDownloader_Win32_Wixud_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Wixud.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 10 80 fa 7e 0f 85 90 03 01 01 d2 d4 00 00 00 a3 90 01 02 40 00 ff 05 90 01 02 40 00 40 3b c8 0f 84 90 03 01 01 be c0 00 00 00 8a 10 80 fa 7e 75 f0 c6 00 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}