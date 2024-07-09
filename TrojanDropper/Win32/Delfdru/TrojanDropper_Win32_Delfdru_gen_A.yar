
rule TrojanDropper_Win32_Delfdru_gen_A{
	meta:
		description = "TrojanDropper:Win32/Delfdru.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e8 01 72 07 74 18 48 74 28 eb 37 8d 85 00 ff ff ff 50 68 00 01 00 00 e8 ?? ?? ?? ff eb 24 68 00 01 00 00 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ff eb 11 68 00 01 00 00 8d 85 00 ff ff ff 50 e8 ?? ?? ?? ff 83 fb 02 75 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}