
rule PWS_BAT_StormKitty_GB_MTB{
	meta:
		description = "PWS:BAT/StormKitty.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 0f 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 4c 69 6d 65 72 42 6f 79 2f 53 74 6f 72 6d 4b 69 74 74 79 } //10 https://github.com/LimerBoy/StormKitty
		$a_80_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_2 = {63 61 70 43 72 65 61 74 65 43 61 70 74 75 72 65 57 69 6e 64 6f 77 41 } //capCreateCaptureWindowA  1
		$a_80_3 = {43 72 79 70 74 55 6e 70 72 6f 74 65 63 74 44 61 74 61 } //CryptUnprotectData  1
		$a_80_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //RijndaelManaged  1
		$a_80_5 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_6 = {55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 } //UnhookWindowsHookEx  1
		$a_80_7 = {73 65 74 77 69 6e 64 6f 77 73 68 6f 6f 6b 65 78 } //setwindowshookex  1
	condition:
		((#a_81_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=15
 
}