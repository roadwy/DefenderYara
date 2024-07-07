
rule Trojan_Win32_Stealer_A{
	meta:
		description = "Trojan:Win32/Stealer.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 } //\ProgramData  1
		$a_00_1 = {5c 00 66 00 62 00 00 00 5c 00 46 00 61 00 63 00 65 00 62 00 6f 00 6f 00 6b 00 52 00 6f 00 62 00 6f 00 74 00 2e 00 64 00 6c 00 6c 00 } //2
		$a_80_2 = {46 61 63 65 62 6f 6f 6b 52 6f 62 6f 74 2e 6c 69 62 } //FacebookRobot.lib  2
		$a_80_3 = {4f 62 6a 5c 52 65 6c 65 61 73 65 5c 53 68 61 72 70 58 2e 70 64 62 } //Obj\Release\SharpX.pdb  1
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1) >=3
 
}