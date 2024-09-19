
rule Trojan_Win32_Clipbanker_AMAG_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.AMAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 6c 69 70 c7 45 ?? 62 6f 61 72 66 c7 45 ?? 64 00 c7 45 ?? 43 6c 6f 73 c7 45 ?? 65 43 6c 69 c7 45 ?? 70 62 6f 61 66 c7 45 ?? 72 64 c6 45 ?? 00 c6 45 ?? 00 c7 45 ?? 45 6d 70 74 c7 45 ?? 79 43 6c 69 c7 45 ?? 70 62 6f 61 66 c7 45 ?? 72 64 } //2
		$a_01_1 = {80 01 fd 8d 49 01 42 3b d7 75 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}