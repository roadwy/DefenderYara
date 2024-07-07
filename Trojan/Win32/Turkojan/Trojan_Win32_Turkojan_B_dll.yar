
rule Trojan_Win32_Turkojan_B_dll{
	meta:
		description = "Trojan:Win32/Turkojan.B!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 73 6f 63 6b 33 32 5f 68 6f 6f 6b 2e 64 6c 6c 00 44 4c 4c 49 6e 6a 65 63 74 65 64 41 64 64 00 44 4c 4c 52 65 6d 6f 76 65 00 } //1 獷捯㍫弲潨歯搮汬䐀䱌湉敪瑣摥摁d䱄剌浥癯e
		$a_01_1 = {44 4c 4d 4e 49 55 6d 73 6e 00 00 00 09 6d 73 74 77 61 69 6e 33 32 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}