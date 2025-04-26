
rule TrojanDropper_Win32_Ifnapod_A{
	meta:
		description = "TrojanDropper:Win32/Ifnapod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 00 24 00 00 ff 74 24 10 90 09 18 00 68 00 00 00 80 56 ff 15 ?? ?? ?? ?? 53 50 89 44 24 18 ff 15 } //1
		$a_02_1 = {c6 85 01 ff ff ff 4e c6 85 00 ff ff ff 57 ff 15 90 09 2f 00 6a 3a be ?? ?? ?? 00 8d bd 00 ff ff ff f3 a5 59 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}