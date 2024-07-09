
rule TrojanSpy_BAT_Logkayi_A{
	meta:
		description = "TrojanSpy:BAT/Logkayi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4a 00 34 00 5a 00 4c 00 42 00 4c 00 79 00 65 00 31 00 58 00 55 00 49 00 4e 00 51 00 61 00 5a 00 58 00 38 00 6a 00 77 00 64 00 41 00 3d 00 3d 00 } //1 J4ZLBLye1XUINQaZX8jwdA==
		$a_02_1 = {2e 00 53 00 43 00 52 00 ?? ?? 23 00 67 00 65 00 74 00 65 00 64 00 65 00 72 00 23 00 } //1
		$a_01_2 = {67 66 78 53 63 72 65 65 6e 73 68 6f 74 } //1 gfxScreenshot
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}