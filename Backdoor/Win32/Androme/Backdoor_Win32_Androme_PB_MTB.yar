
rule Backdoor_Win32_Androme_PB_MTB{
	meta:
		description = "Backdoor:Win32/Androme.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {46 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8b 84 b5 ?? ?? ?? ?? 03 45 ?? 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 89 45 f0 8a 84 b5 ?? ?? ?? ?? 8b 55 ?? 8b 94 95 ?? ?? ?? ?? 89 94 b5 ?? ?? ?? ?? 25 ff 00 00 00 8b 55 ?? 89 84 95 ?? ?? ?? ?? 8b 84 b5 ?? ?? ?? ?? 8b 55 ?? 03 84 95 ?? ?? ?? ?? 25 ff 00 00 80 79 07 48 0d 00 ff ff ff 40 8a 84 85 ?? ?? ?? ?? 8b 55 ?? 30 04 3a 47 4b 0f 85 } //10
		$a_01_1 = {3a 5c 20 43 6f 6e 6e 65 63 74 65 64 } //1 :\ Connected
		$a_01_2 = {45 6a 65 63 74 20 55 53 42 } //1 Eject USB
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}