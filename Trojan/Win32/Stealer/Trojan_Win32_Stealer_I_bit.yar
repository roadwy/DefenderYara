
rule Trojan_Win32_Stealer_I_bit{
	meta:
		description = "Trojan:Win32/Stealer.I!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 f8 68 ?? ?? ?? ?? 8b 45 f8 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d f8 51 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 6a 08 ff 15 ?? ?? ?? ?? 89 45 f4 c7 45 fc ff ff ff ff 8d 95 c8 fb ff ff 52 8b 45 f4 50 ff 15 ?? ?? ?? ?? 85 c0 75 0c 8b 4d f4 51 e8 } //1
		$a_03_1 = {8b 45 08 0f b6 08 0f b6 55 14 c1 e2 ?? 81 e2 c0 00 00 00 0b ca 8b 45 08 88 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}