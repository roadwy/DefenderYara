
rule Trojan_Win32_Emotetcrypt_HZ_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 d1 2b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 03 d0 8b 0d ?? ?? ?? ?? 0f af 0d ?? ?? ?? ?? 03 d1 8b 45 f0 03 05 ?? ?? ?? ?? 8b 4d 08 0f b6 04 01 8b 4d 0c 0f b6 14 11 33 d0 a1 ?? ?? ?? ?? 0f af 05 ?? ?? ?? ?? 8b 0d } //1
		$a_81_1 = {79 28 33 5a 6f 64 74 59 38 7a 41 5f 78 49 23 23 5f 50 30 67 3e 71 78 36 5e 21 5f 49 47 6e 4d 76 54 6d 2a 7a 26 73 62 72 40 6e 59 } //1 y(3ZodtY8zA_xI##_P0g>qx6^!_IGnMvTm*z&sbr@nY
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}