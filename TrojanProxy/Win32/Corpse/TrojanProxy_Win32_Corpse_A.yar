
rule TrojanProxy_Win32_Corpse_A{
	meta:
		description = "TrojanProxy:Win32/Corpse.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {81 c4 2c e4 ff ff 68 d4 1b 00 00 8d 85 2c e4 ff ff 50 e8 ?? ?? ?? ?? 81 7d 08 36 36 36 36 0f 84 } //1
		$a_01_1 = {6a 00 68 88 13 00 00 8d 85 a0 e9 ff ff 50 ff b5 2c fd ff ff e8 } //1
		$a_01_2 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 5c 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}