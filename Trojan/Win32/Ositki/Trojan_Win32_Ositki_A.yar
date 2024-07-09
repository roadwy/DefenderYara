
rule Trojan_Win32_Ositki_A{
	meta:
		description = "Trojan:Win32/Ositki.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {33 ff 47 6a 3b ff 74 24 ?? ff 15 ?? ?? 14 13 8b f0 3b f3 74 53 6a 3b 46 56 ff 15 ?? ?? 14 13 3b c3 8b 0d } //4
		$a_00_1 = {69 64 3d 25 75 26 63 6d 64 3d 25 64 26 6e 74 3d 25 64 26 62 76 3d 25 73 26 6c 74 3d 25 73 } //1 id=%u&cmd=%d&nt=%d&bv=%s&lt=%s
		$a_00_2 = {69 64 3d 25 75 26 63 6d 64 3d 25 64 26 6a 69 64 3d 25 75 26 6a 73 74 61 74 3d 25 75 } //1 id=%u&cmd=%d&jid=%u&jstat=%u
		$a_00_3 = {69 64 3d 25 75 26 63 6d 64 3d 25 64 26 63 6f 6f 6b 69 65 3d 25 73 } //1 id=%u&cmd=%d&cookie=%s
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}