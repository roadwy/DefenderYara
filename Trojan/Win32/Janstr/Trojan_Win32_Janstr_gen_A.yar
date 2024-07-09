
rule Trojan_Win32_Janstr_gen_A{
	meta:
		description = "Trojan:Win32/Janstr.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,6d 00 68 00 0a 00 00 "
		
	strings :
		$a_02_0 = {53 8b d8 8b 83 04 03 00 00 8b 10 ff 92 e0 00 00 00 b2 01 8b 83 10 03 00 00 e8 ?? ?? ?? ?? 5b c3 } //100
		$a_00_1 = {5c 77 65 62 6d 61 6c 2e 65 78 74 74 74 } //1 \webmal.exttt
		$a_00_2 = {6b 69 6d 65 63 65 6b 2e 61 73 70 } //1 kimecek.asp
		$a_00_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 61 6a 61 6e 73 74 65 72 2e 63 6f 6d 2f 7a 75 70 70 65 2f } //1 http://www.ajanster.com/zuppe/
		$a_00_4 = {2b 25 a3 a3 23 24 bd 7b 7b 3f 3d 29 5f 3f 3d 00 } //1
		$a_00_5 = {6d 61 69 6c 6c 69 73 74 63 65 6b 2e 61 73 70 } //1 maillistcek.asp
		$a_00_6 = {5c 70 72 6f 68 61 74 61 } //1 \prohata
		$a_00_7 = {77 65 62 6d 61 69 6c 67 6f 6e 64 65 72 32 } //1 webmailgonder2
		$a_00_8 = {6d 73 6e 67 69 72 69 73 } //1 msngiris
		$a_00_9 = {49 64 41 6e 74 69 46 72 65 65 7a 65 31 } //1 IdAntiFreeze1
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=104
 
}