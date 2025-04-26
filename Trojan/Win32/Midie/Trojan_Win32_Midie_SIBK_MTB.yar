
rule Trojan_Win32_Midie_SIBK_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 62 72 65 61 6b 74 68 72 6f 75 67 68 5c 69 6e 74 65 67 72 61 6c 2e 64 6c 6c } //1 \breakthrough\integral.dll
		$a_00_1 = {5c 64 69 73 61 67 72 65 65 6d 65 6e 74 73 2e 61 75 } //1 \disagreements.au
		$a_03_2 = {68 80 00 00 00 6a 03 56 6a 07 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 56 8d 4d ?? be ?? ?? ?? ?? 51 56 8d 8d ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 90 1b 03 81 f9 90 1b 02 74 ?? [0-08] 2c ?? [0-08] 34 ?? [0-15] 2c ?? [0-05] 04 ?? 88 84 0d 90 1b 03 83 c1 01 90 18 8a 84 0d 90 1b 03 81 f9 90 1b 02 90 18 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? 90 1b 16 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 6a 40 56 8d 8d 90 1b 03 51 ff d0 8d 85 90 1b 03 ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}