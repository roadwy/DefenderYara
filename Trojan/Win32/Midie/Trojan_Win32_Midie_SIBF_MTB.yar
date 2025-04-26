
rule Trojan_Win32_Midie_SIBF_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 74 72 61 70 70 65 64 2e 70 64 66 } //1 \trapped.pdf
		$a_00_1 = {5c 68 6f 74 64 6f 67 2e 64 6c 6c } //1 \hotdog.dll
		$a_03_2 = {6a 40 57 8d 8d ?? ?? ?? ?? 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 8d 4d ?? 51 57 8d 8d 90 1b 00 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 90 1b 00 81 f9 ?? ?? ?? ?? 74 ?? [0-05] 04 2d 34 24 [0-08] 2c 77 [0-08] 04 ea [0-05] 34 65 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 07 90 18 b0 00 b9 00 00 00 00 8d 85 90 1b 00 ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}