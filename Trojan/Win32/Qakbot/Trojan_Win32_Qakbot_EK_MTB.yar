
rule Trojan_Win32_Qakbot_EK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 a8 03 55 ac 4a 2b d0 89 55 a4 } //3
		$a_01_1 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}
rule Trojan_Win32_Qakbot_EK_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //10 DllRegisterServer
		$a_01_1 = {6a 6e 53 59 67 64 48 62 2e 64 6c 6c } //1 jnSYgdHb.dll
		$a_01_2 = {41 66 6d 71 56 53 43 } //1 AfmqVSC
		$a_01_3 = {42 33 67 74 71 78 45 65 6a } //1 B3gtqxEej
		$a_01_4 = {43 31 74 65 63 58 65 62 73 } //1 C1tecXebs
		$a_01_5 = {44 36 70 6e 38 4d 7a 41 } //1 D6pn8MzA
		$a_01_6 = {49 55 72 67 4c 50 51 72 2e 64 6c 6c } //1 IUrgLPQr.dll
		$a_01_7 = {42 78 68 6c 7a 70 41 59 } //1 BxhlzpAY
		$a_01_8 = {43 6a 58 4e 7a 79 34 6c 42 } //1 CjXNzy4lB
		$a_01_9 = {46 37 4d 49 6c 63 37 6b 4a 6e 6d } //1 F7MIlc7kJnm
		$a_01_10 = {4a 57 73 6c 37 59 69 56 57 } //1 JWsl7YiVW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=15
 
}