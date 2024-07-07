
rule Trojan_Win32_BHO_DG_dll{
	meta:
		description = "Trojan:Win32/BHO.DG!dll,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 00 6f 00 70 00 47 00 75 00 69 00 64 00 65 00 2e 00 65 00 78 00 65 00 } //1 TopGuide.exe
		$a_01_1 = {69 00 6e 00 66 00 6f 00 2d 00 77 00 61 00 79 00 2e 00 6b 00 72 00 2f 00 61 00 64 00 64 00 50 00 61 00 67 00 65 00 73 00 2f 00 3f 00 69 00 64 00 3d 00 25 00 73 00 26 00 6b 00 3d 00 25 00 73 00 } //1 info-way.kr/addPages/?id=%s&k=%s
		$a_01_2 = {5c ed 94 84 eb a1 9c ec a0 9d ed 8a b8 5c 74 6f 70 67 75 69 64 65 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}