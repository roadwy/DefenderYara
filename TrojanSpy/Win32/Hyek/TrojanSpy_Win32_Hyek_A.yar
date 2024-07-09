
rule TrojanSpy_Win32_Hyek_A{
	meta:
		description = "TrojanSpy:Win32/Hyek.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {5c 68 79 62 72 69 64 6c 6f 67 [0-10] 5c 6e 6f 6c 6f 67 67 65 72 } //1
		$a_03_1 = {64 79 62 61 72 74 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 53 79 73 41 64 6d 69 6e 2e 65 78 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}