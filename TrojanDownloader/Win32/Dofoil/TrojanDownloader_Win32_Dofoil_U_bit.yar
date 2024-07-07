
rule TrojanDownloader_Win32_Dofoil_U_bit{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.U!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 07 88 10 8b 55 fc 41 40 3b ca 72 f2 68 90 01 04 6a 40 52 56 ff 15 90 00 } //1
		$a_03_1 = {30 14 30 40 3b 45 fc 7c e6 89 0d 90 01 04 ff 55 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}