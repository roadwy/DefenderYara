
rule Trojan_Win32_FirmLoad_A_dha{
	meta:
		description = "Trojan:Win32/FirmLoad.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 33 c9 45 33 c0 33 d2 b9 42 4d 53 52 ff 15 } //3
		$a_03_1 = {ba 02 00 00 00 41 b8 00 00 00 10 ?? ?? ?? [0-03] ff 15 ?? ?? ?? ?? 85 c0 ?? ?? ?? ?? ?? ?? ?? ?? [0-06] ba 02 00 00 00 41 b8 00 00 00 10 ?? ?? ?? [0-03] ff 15 } //1
		$a_01_2 = {8b 0e 8b d1 8b c1 c1 e9 08 c1 e2 10 25 00 ff 00 00 81 e1 00 ff 00 00 0b d0 0f b6 46 03 c1 e2 08 0b d1 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}