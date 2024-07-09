
rule TrojanDropper_Win32_Alobtoe_A{
	meta:
		description = "TrojanDropper:Win32/Alobtoe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 64 ff 30 64 89 20 00 00 68 ?? ?? 40 00 33 c0 64 ff 30 64 89 20 00 00 81 c4 b0 07 00 00 } //1
		$a_03_1 = {3d 40 00 00 00 83 c4 28 68 ?? ?? 40 00 e8 c3 03 00 00 a3 ?? ?? 40 00 90 90 90 90 90 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}