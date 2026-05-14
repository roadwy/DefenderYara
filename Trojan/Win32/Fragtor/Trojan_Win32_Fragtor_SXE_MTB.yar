
rule Trojan_Win32_Fragtor_SXE_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 00 8b 58 18 89 9d 54 fe ff ff 8b 00 8b 40 18 89 85 50 fe ff ff 0f 28 05 ?? ?? ?? ?? 8d 45 e8 50 ff b5 54 fe ff ff 0f 11 45 e8 c7 45 f8 65 61 64 00 ff 15 } //20
		$a_80_1 = {45 74 77 70 43 72 65 61 74 65 45 74 77 54 68 72 28 6a } //EtwpCreateEtwThr(j  30
		$a_03_2 = {8b f0 c7 45 f4 47 45 54 47 6a 07 8d 45 f4 66 c7 45 f8 4f 44 50 ff 35 ?? ?? ?? ?? c6 45 fa 00 ff 15 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_80_1  & 1)*30+(#a_03_2  & 1)*10) >=60
 
}