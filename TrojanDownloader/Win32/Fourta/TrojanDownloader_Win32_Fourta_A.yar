
rule TrojanDownloader_Win32_Fourta_A{
	meta:
		description = "TrojanDownloader:Win32/Fourta.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {74 4f 68 ff ff 00 00 8d 85 fd ff fe ff 50 ff b5 dc ff fe ff e8 ?? ?? 00 00 8d 85 fd ff fe ff 50 e8 ?? ?? 00 00 59 ba 0a 00 00 00 39 c2 7f 08 6a 01 e8 ?? ?? 00 00 59 68 ef cd 00 00 68 dc fe 00 00 68 00 04 00 00 } //1
		$a_00_1 = {ff 85 d0 fe fe ff 81 bd d0 fe fe ff 6c 07 00 00 72 e7 ff 85 f4 ff fe ff 81 bd f4 ff fe ff 90 5f 01 00 72 cc } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}