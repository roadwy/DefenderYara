
rule Trojan_Win32_Emotetcrypt_FE_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.FE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c1 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 8b 45 f4 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 4d 0c 88 14 01 } //1
		$a_81_1 = {72 25 24 57 54 4e 42 66 44 58 56 2b 53 4e 36 4f 40 46 49 5f 6d 54 32 4d 67 52 7a 46 2a 78 61 56 4a 62 46 4b 4c 66 69 35 4d 70 64 38 46 4a 3c 62 35 } //1 r%$WTNBfDXV+SN6O@FI_mT2MgRzF*xaVJbFKLfi5Mpd8FJ<b5
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}