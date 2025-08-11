
rule Trojan_Win32_Jaik_KK_MTB{
	meta:
		description = "Trojan:Win32/Jaik.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 8d e4 fd ff ff 03 c2 8b 95 e0 fd ff ff 0f b6 c0 0f b6 84 05 f0 fe ff ff 30 04 0a } //30
		$a_03_1 = {03 c8 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 8a 84 0d ?? ?? ?? ?? 88 84 3d 90 1b 01 47 89 8d ?? ?? ff ff 88 9c 0d 90 1b 02 81 ff } //20
		$a_01_2 = {6d 73 67 64 65 75 70 64 61 74 65 2e 65 78 65 } //10 msgdeupdate.exe
	condition:
		((#a_01_0  & 1)*30+(#a_03_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}