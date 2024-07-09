
rule TrojanDownloader_Win32_Grepise_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Grepise.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 3e 8b cf 2c ?? 34 ?? 88 04 3e 46 8d 51 01 8a 01 41 84 c0 75 f9 2b ca 3b f1 72 e3 } //1
		$a_03_1 = {0f be c1 83 f0 ?? 83 c0 ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}