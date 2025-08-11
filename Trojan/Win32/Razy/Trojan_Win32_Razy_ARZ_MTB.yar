
rule Trojan_Win32_Razy_ARZ_MTB{
	meta:
		description = "Trojan:Win32/Razy.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 85 5c ff ff ff 56 c6 85 5d ff ff ff 69 c6 85 5e ff ff ff 72 c6 85 5f ff ff ff 74 c6 85 60 ff ff ff 75 c6 85 61 ff ff ff 61 c6 85 62 ff ff ff 6c c6 85 63 ff ff ff 41 c6 85 64 ff ff ff 6c c6 85 65 ff ff ff 6c c6 85 66 ff ff ff 6f c6 85 67 ff ff ff 63 } //3
		$a_01_1 = {c6 85 4c ff ff ff 43 c6 85 4d ff ff ff 72 c6 85 4e ff ff ff 65 c6 85 4f ff ff ff 61 c6 85 50 ff ff ff 74 c6 85 51 ff ff ff 65 c6 85 52 ff ff ff 54 c6 85 53 ff ff ff 68 c6 85 54 ff ff ff 72 c6 85 55 ff ff ff 65 c6 85 56 ff ff ff 61 c6 85 57 ff ff ff 64 } //2
		$a_01_2 = {c6 45 98 57 c6 45 99 69 c6 45 9a 6e c6 45 9b 45 c6 45 9c 78 c6 45 9d 65 c6 45 9e 63 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}