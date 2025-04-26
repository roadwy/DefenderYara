
rule Trojan_Win32_Midie_SIBG_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 73 74 65 70 66 61 74 68 65 72 5c 62 6f 77 65 6c 73 2e 70 64 66 } //1 \stepfather\bowels.pdf
		$a_00_1 = {5c 61 69 72 77 61 76 65 73 5c 6c 65 6d 6f 6e 61 64 65 2e 62 6d 70 } //1 \airwaves\lemonade.bmp
		$a_03_2 = {b9 00 00 00 00 8a 84 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? [0-05] 04 ?? [0-08] 2c af [0-05] 2c 95 88 84 0d 90 1b 00 83 c1 01 90 18 8a 84 0d 90 1b 00 81 f9 90 1b 01 90 18 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? 90 1b 0d ff 15 ?? 90 1b 0d 50 ff 15 ?? 90 1b 0d 8d 4d ?? 51 6a ?? 56 8d 8d 90 1b 00 51 ff d0 8d 85 90 1b 00 ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}