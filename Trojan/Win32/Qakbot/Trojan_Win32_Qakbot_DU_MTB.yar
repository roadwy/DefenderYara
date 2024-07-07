
rule Trojan_Win32_Qakbot_DU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {31 6d 2e 64 6c 6c } //1 1m.dll
		$a_01_2 = {42 61 74 61 4d 36 6f 68 6f 6f } //1 BataM6ohoo
		$a_01_3 = {44 69 49 58 70 56 37 56 7a 70 } //1 DiIXpV7Vzp
		$a_01_4 = {44 59 63 66 43 42 78 53 } //1 DYcfCBxS
		$a_01_5 = {41 46 64 39 72 48 4d 31 61 } //1 AFd9rHM1a
		$a_01_6 = {4b 66 2e 64 6c 6c } //1 Kf.dll
		$a_01_7 = {42 75 50 57 43 38 32 71 4a 57 57 } //1 BuPWC82qJWW
		$a_01_8 = {43 36 38 7a 4e 4e 72 55 61 6f } //1 C68zNNrUao
		$a_01_9 = {43 7a 4a 4b 34 7a 6a 70 4e 69 55 } //1 CzJK4zjpNiU
		$a_01_10 = {44 51 4f 70 43 35 73 4b 67 43 } //1 DQOpC5sKgC
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}