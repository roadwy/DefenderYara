
rule Trojan_Win32_BHO_BH{
	meta:
		description = "Trojan:Win32/BHO.BH,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 3f 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 70 61 73 73 31 3d 25 73 26 74 69 74 6c 65 3d 25 73 } //01 00  %s?user=%s&pass=%s&pass1=%s&title=%s
		$a_00_1 = {25 73 3f 75 73 65 72 3d 25 73 26 70 61 73 73 3d 25 73 26 74 69 74 6c 65 3d 25 73 26 75 72 6c 3d 25 73 } //0a 00  %s?user=%s&pass=%s&title=%s&url=%s
		$a_00_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //0a 00  InternetOpenUrlA
		$a_01_3 = {47 65 74 48 74 6d 6c 50 77 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00  敇䡴浴偬摷䐮䱌䐀汬慃啮汮慯乤睯
	condition:
		any of ($a_*)
 
}