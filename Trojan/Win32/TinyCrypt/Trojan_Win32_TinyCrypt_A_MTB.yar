
rule Trojan_Win32_TinyCrypt_A_MTB{
	meta:
		description = "Trojan:Win32/TinyCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 90 01 01 ff ff ff 81 bd 90 01 01 ff ff ff 90 01 04 0f 83 99 00 00 00 8b 8d 90 01 01 ff ff ff 8b 55 90 01 01 8b 04 8a 89 85 90 01 01 ff ff ff 8b 0d 90 01 04 89 8d 90 01 01 ff ff ff 8b 95 90 01 01 ff ff ff 2b 95 90 01 01 ff ff ff 89 95 90 01 01 ff ff ff 8b 45 84 c1 e0 13 89 45 84 8b 8d 90 01 01 ff ff ff 33 8d 90 01 01 ff ff ff 89 8d 90 01 01 ff ff ff 8b 55 84 81 c2 00 00 10 00 89 55 90 01 01 c1 85 90 01 01 ff ff ff 07 8b 45 84 99 81 e2 ff ff 0f 00 03 c2 c1 f8 14 89 45 84 8b 85 90 01 01 ff ff ff 33 85 90 01 01 ff ff ff 89 85 90 01 01 ff ff ff 8b 8d 90 01 01 ff ff ff 8b 55 90 01 01 8b 85 90 01 01 ff ff ff 89 04 8a e9 90 01 01 ff ff ff 90 00 } //1
		$a_01_1 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 52 65 70 65 61 74 } //1 if exist "%s" goto Repeat
		$a_01_2 = {64 65 6c 20 20 22 25 73 22 } //1 del  "%s"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}