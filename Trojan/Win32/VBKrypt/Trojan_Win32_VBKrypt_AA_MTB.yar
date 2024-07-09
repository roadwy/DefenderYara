
rule Trojan_Win32_VBKrypt_AA_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 1c 50 8b 4d 08 8b 31 8d 55 d0 52 ff 15 ?? ?? ?? ?? 8b 4d 08 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84 } //1
		$a_02_1 = {8b c8 8b c6 99 f7 f9 8b 45 ac 66 33 1c 50 8b 4d 0c 8b 31 8d 55 d0 52 ff 15 ?? ?? ?? ?? 8b 4d 0c 8b 11 2b 42 14 8b 4e 0c 88 1c 01 8d 4d 84 } //1
		$a_00_2 = {5c 00 64 00 72 00 61 00 63 00 75 00 6c 00 6c 00 43 00 61 00 6c 00 65 00 6e 00 64 00 61 00 72 00 2e 00 70 00 64 00 66 00 } //1 \dracullCalendar.pdf
		$a_00_3 = {5f 00 66 00 6f 00 72 00 64 00 2e 00 6a 00 70 00 67 00 } //1 _ford.jpg
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}