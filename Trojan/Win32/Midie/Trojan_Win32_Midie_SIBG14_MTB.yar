
rule Trojan_Win32_Midie_SIBG14_MTB{
	meta:
		description = "Trojan:Win32/Midie.SIBG14!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 6e 00 61 00 6d 00 65 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 3e 00 } //1 <program name unknown>
		$a_03_1 = {8b 55 08 b8 ?? ?? ?? ?? 90 18 8a 0a 84 c9 90 18 6b c0 ?? 0f be c9 03 c1 42 } //1
		$a_03_2 = {6a 40 68 00 30 00 00 8b d8 53 57 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-0a] 34 ?? [0-0a] 2c ?? [0-0a] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}