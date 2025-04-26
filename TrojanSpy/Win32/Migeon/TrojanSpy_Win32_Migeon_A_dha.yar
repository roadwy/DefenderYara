
rule TrojanSpy_Win32_Migeon_A_dha{
	meta:
		description = "TrojanSpy:Win32/Migeon.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 c2 fe 09 00 00 b9 ff 01 00 00 } //5
		$a_03_1 = {b9 00 16 00 00 8b 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 02 02 00 00 b9 ff 01 00 00 } //5
		$a_00_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 25 00 73 00 2c 00 50 00 6c 00 61 00 79 00 65 00 72 00 } //1 rundll32.exe %s,Player
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1) >=11
 
}