
rule Trojan_Win32_Qakbot_DV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {55 6c 2e 64 6c 6c } //1 Ul.dll
		$a_01_2 = {41 59 32 58 42 35 6a 4f 66 41 } //1 AY2XB5jOfA
		$a_01_3 = {42 74 63 77 64 4f 72 30 31 } //1 BtcwdOr01
		$a_01_4 = {43 4d 64 72 61 71 75 69 } //1 CMdraqui
		$a_01_5 = {44 47 6d 58 78 57 56 50 44 } //1 DGmXxWVPD
		$a_01_6 = {4f 4a 2e 64 6c 6c } //1 OJ.dll
		$a_01_7 = {41 35 50 73 4b 55 38 58 76 47 } //1 A5PsKU8XvG
		$a_01_8 = {42 4a 39 70 38 44 35 4f 54 } //1 BJ9p8D5OT
		$a_01_9 = {43 44 6a 4d 4b 32 31 38 7a 72 57 } //1 CDjMK218zrW
		$a_01_10 = {44 35 56 4d 47 75 47 34 } //1 D5VMGuG4
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}