
rule TrojanDownloader_Win32_Uoolop_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Uoolop.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 32 8b fe 34 ?? 83 c9 ff 2a c2 34 ?? 88 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}