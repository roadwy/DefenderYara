
rule Trojan_Win32_NsCoinminer{
	meta:
		description = "Trojan:Win32/NsCoinminer,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_02_0 = {b9 00 01 00 00 e8 90 02 25 c6 85 90 01 02 ff ff 0b c6 85 90 01 02 ff ff 64 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 74 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 2e c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 62 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 6e c6 85 90 01 02 ff ff 02 8d 95 90 01 02 ff ff 90 00 } //1
		$a_02_1 = {b9 00 01 00 00 e8 90 02 25 c6 85 90 01 02 ff ff 0b c6 45 90 01 01 64 c6 45 90 01 01 02 c6 45 90 01 01 61 c6 45 90 01 01 02 c6 45 90 01 01 74 c6 45 90 01 01 02 c6 45 90 01 01 61 c6 45 90 01 01 02 c6 45 90 01 01 2e c6 45 90 01 01 02 c6 45 90 01 01 62 c6 45 90 01 01 02 c6 45 90 01 01 69 c6 45 90 01 01 02 c6 45 90 01 01 6e c6 45 90 01 01 02 8d 95 90 01 02 ff ff 90 00 } //1
		$a_02_2 = {ff ff 50 c6 85 90 01 02 ff ff 44 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 6c c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 4d c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 61 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 69 c6 85 90 01 02 ff ff 02 c6 85 90 01 02 ff ff 6e c6 85 90 01 02 ff ff 02 8d 95 90 01 02 ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}