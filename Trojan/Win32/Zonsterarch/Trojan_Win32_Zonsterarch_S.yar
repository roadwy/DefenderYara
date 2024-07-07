
rule Trojan_Win32_Zonsterarch_S{
	meta:
		description = "Trojan:Win32/Zonsterarch.S,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 4d 5f 53 4d 53 05 50 4d 5f 57 4d 06 50 4d 5f 49 56 52 09 50 4d 5f 50 61 79 50 61 6c 09 50 4d 5f 43 72 65 64 69 74 05 50 4d 5f 56 4b } //1
		$a_01_1 = {61 6c 74 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 61 70 69 5f 62 61 73 65 5f 75 72 6c 00 00 00 00 ff ff ff ff 10 00 00 00 61 6c 74 5f 70 61 79 5f 62 61 73 65 5f 75 72 6c } //1
		$a_01_2 = {6c 62 6c 53 6d 73 43 6f 75 6e 74 } //1 lblSmsCount
		$a_01_3 = {25 00 64 00 20 00 53 00 4d 00 53 00 2d 00 } //1 %d SMS-
		$a_01_4 = {5c 5a 69 70 4d 6f 6e 73 74 65 72 5c 53 6f 66 74 5c 53 6f 75 72 63 65 73 5c } //1 \ZipMonster\Soft\Sources\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}