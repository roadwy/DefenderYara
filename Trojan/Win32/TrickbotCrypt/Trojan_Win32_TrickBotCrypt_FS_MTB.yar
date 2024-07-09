
rule Trojan_Win32_TrickBotCrypt_FS_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.FS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0f 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d8 0f af d8 4b 0f af d8 a1 ?? ?? ?? ?? 03 d3 2b d0 8b 44 24 ?? 8a 14 0a 8a 18 32 da 45 88 18 } //10
		$a_81_1 = {64 6f 55 79 6c 59 67 3c 61 64 23 7a 55 30 2a 31 46 21 26 35 72 3e 64 61 21 4a 5e 66 64 69 4c 48 2b 39 61 41 3f 25 77 3e 57 73 6a 35 79 51 49 44 75 40 45 71 6b 75 4e 69 7a 55 41 44 6b 50 49 48 56 5a 53 4c 5e 53 47 32 38 32 46 61 3f 26 50 25 79 63 41 2a 6b 47 25 56 7a 5f 49 2b 42 54 39 56 4d 61 30 40 66 67 2b 56 5a 46 6d 2b 21 36 31 4b 49 30 37 30 44 58 33 } //10 doUylYg<ad#zU0*1F!&5r>da!J^fdiLH+9aA?%w>Wsj5yQIDu@EqkuNizUADkPIHVZSL^SG282Fa?&P%ycA*kG%Vz_I+BT9VMa0@fg+VZFm+!61KI070DX3
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*10) >=10
 
}