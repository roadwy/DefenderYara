
rule Trojan_Win32_Yoddos_D{
	meta:
		description = "Trojan:Win32/Yoddos.D,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 75 6c 74 69 54 43 50 46 6c 6f 6f 64 00 } //2 畍瑬呩偃汆潯d
		$a_01_1 = {47 6f 6f 67 6c 65 62 6f 74 2f 32 2e 31 3b } //1 Googlebot/2.1;
		$a_03_2 = {b9 01 00 00 00 85 c9 74 57 83 3d ?? ?? ?? ?? 01 75 02 eb 4c b8 63 00 00 00 90 90 b8 9d ff ff ff 90 90 6a 06 6a 01 6a 02 ff 15 ?? ?? ?? ?? 89 85 7c fd ff ff 6a 10 8d 55 f0 52 8b 85 7c fd ff ff 50 ff 15 ?? ?? ?? ?? b8 63 00 00 00 90 90 b8 9d ff ff ff 90 90 8b 8d 7c fd ff ff 51 ff 15 ?? ?? ?? ?? eb a0 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}