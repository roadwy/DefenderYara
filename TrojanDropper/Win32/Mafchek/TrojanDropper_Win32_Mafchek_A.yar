
rule TrojanDropper_Win32_Mafchek_A{
	meta:
		description = "TrojanDropper:Win32/Mafchek.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff b5 78 ff ff ff ff b5 7c ff ff ff 8d 45 80 50 e8 18 01 00 00 68 90 01 04 8d 45 80 50 e8 45 00 00 00 68 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}