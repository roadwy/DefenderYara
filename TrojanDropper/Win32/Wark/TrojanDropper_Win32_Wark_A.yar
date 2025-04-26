
rule TrojanDropper_Win32_Wark_A{
	meta:
		description = "TrojanDropper:Win32/Wark.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 0c b8 68 00 00 00 eb 05 b8 66 00 00 00 8d 8d ?? fc ff ff 51 50 e8 ?? ?? ff ff } //1
		$a_03_1 = {76 16 8d 4c ?? ?? e8 ?? ?? 00 00 8a 14 2e 32 d0 88 14 2e 46 3b f3 72 ea } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}