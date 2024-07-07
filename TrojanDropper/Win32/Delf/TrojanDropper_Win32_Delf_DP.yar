
rule TrojanDropper_Win32_Delf_DP{
	meta:
		description = "TrojanDropper:Win32/Delf.DP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 85 fb fe ff ff 50 68 05 01 00 00 e8 90 01 02 ff ff 8d 85 f4 fe ff ff 8d 95 fb fe ff ff b9 05 01 00 00 e8 90 01 02 ff ff 8b 85 f4 fe ff ff 8b d3 e8 90 00 } //1
		$a_03_1 = {6a 01 6a 00 6a 00 8d 45 fc e8 90 01 02 ff ff 8d 45 fc 8b 15 90 01 04 e8 90 01 02 ff ff 8b 45 fc e8 90 01 02 ff ff 50 6a 00 6a 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}