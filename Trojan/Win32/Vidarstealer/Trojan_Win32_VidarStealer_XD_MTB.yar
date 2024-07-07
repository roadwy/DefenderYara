
rule Trojan_Win32_VidarStealer_XD_MTB{
	meta:
		description = "Trojan:Win32/VidarStealer.XD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b d0 89 7d fc 33 c0 8a 9c 02 90 01 04 8b 7d fc 88 19 8a 9c 07 90 01 04 8b 7d 08 88 5c 07 04 40 41 83 f8 90 00 } //10
		$a_01_1 = {6d 61 73 74 6f 64 6f 6e 2e 6f 6e 6c 69 6e 65 } //1 mastodon.online
		$a_01_2 = {74 2e 6d 65 2f 68 79 69 70 73 64 69 67 65 73 74 } //1 t.me/hyipsdigest
		$a_80_3 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //passwords.txt  1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}