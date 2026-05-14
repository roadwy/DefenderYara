
rule Trojan_Win64_PowDow_SXB_MTB{
	meta:
		description = "Trojan:Win64/PowDow.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 d2 ff 15 ?? ?? ?? ?? 48 8b 55 d8 48 83 fa 10 72 ?? 48 8b 4d c0 48 ff c2 48 8b c1 48 81 fa 00 10 00 00 72 ?? 48 8b 49 f8 48 83 c2 27 48 2b c1 48 83 c0 f8 48 83 f8 1f 0f 87 f9 } //30
		$a_01_1 = {48 8d 4d a0 48 83 7d 18 10 0f 10 00 48 0f 43 55 00 0f 11 45 a0 0f 10 48 10 0f 11 4d b0 48 89 58 10 } //10
		$a_01_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 } //5 powershell.exe -WindowStyle Hidden -Exe
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=45
 
}