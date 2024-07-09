
rule Trojan_Win32_Tionas_A_dha{
	meta:
		description = "Trojan:Win32/Tionas.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {33 c2 8b 4d ?? 03 4d ?? 88 41 } //1
		$a_03_1 = {33 c2 8b 4d ?? 03 4d ?? 88 01 } //1
		$a_03_2 = {83 f9 41 7e ?? 8b 95 04 ff ff ff 0f be 84 15 10 ff ff ff 83 e8 2e 8b 8d 04 ff ff ff 88 84 0d 10 ff ff ff eb } //1
		$a_00_3 = {64 6c 6c 2e 70 6f 6c 79 6d 6f 72 70 68 65 64 2e 64 6c 6c } //4 dll.polymorphed.dll
		$a_00_4 = {37 38 77 4f 31 33 59 72 4a 30 63 42 2e 64 6c 6c } //4 78wO13YrJ0cB.dll
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_00_3  & 1)*4+(#a_00_4  & 1)*4) >=5
 
}