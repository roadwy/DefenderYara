
rule TrojanDownloader_Win32_Silcon_D_bit{
	meta:
		description = "TrojanDownloader:Win32/Silcon.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ad c1 c0 04 c1 c0 01 2b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? ab 81 fe } //1
		$a_03_1 = {6a 00 ff d0 50 8f 05 ?? ?? ?? ?? c3 90 09 20 00 52 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 40 b9 ?? ?? ?? ?? 51 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}