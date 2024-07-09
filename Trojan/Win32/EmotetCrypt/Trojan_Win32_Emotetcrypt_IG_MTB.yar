
rule Trojan_Win32_Emotetcrypt_IG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b c2 2b 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? 2b c2 03 05 ?? ?? ?? ?? 8b 55 08 0f b6 04 02 8b 55 0c 0f b6 0c 0a 33 c8 8b 15 ?? ?? ?? ?? 0f af 15 ?? ?? ?? ?? a1 } //1
		$a_81_1 = {6b 2b 24 36 79 4c 46 42 78 70 32 26 58 6f 34 57 75 74 7a 6d 54 21 34 49 58 70 72 6a 54 75 24 3e 32 2b 4a 51 47 46 26 4e 21 39 37 23 69 33 25 41 3c } //1 k+$6yLFBxp2&Xo4WutzmT!4IXprjTu$>2+JQGF&N!97#i3%A<
		$a_81_2 = {73 65 73 41 72 4c 67 28 30 55 44 58 34 50 79 57 50 79 28 45 51 38 56 74 4a 6b 61 34 3c 39 5a 55 24 3e 48 49 25 35 34 3f 40 54 66 2b 42 62 46 5f 29 59 57 2a 21 73 56 4d 76 4d 34 79 61 25 37 62 43 47 6b 71 42 67 48 4d 26 37 49 72 3f 49 2a 34 59 75 63 4d 52 } //1 sesArLg(0UDX4PyWPy(EQ8VtJka4<9ZU$>HI%54?@Tf+BbF_)YW*!sVMvM4ya%7bCGkqBgHM&7Ir?I*4YucMR
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=1
 
}