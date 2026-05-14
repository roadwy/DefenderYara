
rule Trojan_Win64_SantaStealer_ABSS_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.ABSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ca 45 33 c1 41 89 4c 9b ?? 48 8d 53 06 41 8b c0 24 ?? f6 d8 1b c9 81 e1 ?? ?? ?? ?? 41 33 8c 9b ?? ?? ?? ?? 48 8b da 41 d1 e8 41 33 c8 41 89 0c 93 48 81 fa } //3
		$a_80_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 } //powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command   2
	condition:
		((#a_03_0  & 1)*3+(#a_80_1  & 1)*2) >=5
 
}