
rule TrojanDownloader_Win32_Uoolop_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Uoolop.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 04 32 8b fe 34 cb 83 c9 ff 2a c2 34 73 88 04 32 } //1
		$a_01_1 = {8a c2 b1 03 2c 27 8b fe f6 e9 8a 0c 32 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}