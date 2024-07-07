
rule Trojan_Win32_Startpage_ACG_dll{
	meta:
		description = "Trojan:Win32/Startpage.ACG!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 34 35 30 45 41 35 46 43 36 39 31 42 44 38 44 42 37 38 43 38 41 39 43 36 32 } //1 F450EA5FC691BD8DB78C8A9C62
		$a_03_1 = {2e 6f 6b 67 61 6d 65 64 6f 77 6e 2e 63 6e 2f 90 01 0b 2e 68 74 6d 6c 3f 90 00 } //1
		$a_01_2 = {56 61 67 61 61 cd db b8 c2 bb ad ca b1 b4 fa 00 } //1
		$a_01_3 = {46 3a 5c b9 e3 b8 e6 5c b5 bc ba bd 31 30 30 38 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}