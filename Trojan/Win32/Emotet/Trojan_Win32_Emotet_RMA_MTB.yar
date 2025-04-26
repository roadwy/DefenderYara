
rule Trojan_Win32_Emotet_RMA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b c1 50 56 33 db 53 6a ff ff 15 ?? ?? ?? ?? 8b 6c 24 ?? eb } //1
		$a_80_1 = {3e 42 25 6c 49 32 28 25 61 70 40 58 5e 6b 63 3e 6f 6b 29 37 32 51 44 68 4d 50 59 30 76 5f 3e 5f 49 6e 74 66 76 3c 48 7a 49 50 55 62 52 35 32 7a 30 57 64 4a 61 26 58 33 30 79 3f 43 65 23 78 53 33 39 2b 4c 55 4a 64 3c 4f 35 66 5f } //>B%lI2(%ap@X^kc>ok)72QDhMPY0v_>_Intfv<HzIPUbR52z0WdJa&X30y?Ce#xS39+LUJd<O5f_  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {47 5f 55 37 66 52 5f 74 4e 3e 51 33 6b 30 53 5f 64 61 74 34 50 2a 57 59 3c 4a 73 38 2b 29 43 2a 21 64 3f 76 21 71 21 3f 4f 5f 36 75 56 78 63 31 35 74 3c 3e 44 56 25 72 40 37 4a 55 66 79 78 32 79 63 62 43 78 4b 40 6c 64 58 26 43 23 4b 29 3f 45 3c 40 59 75 2b 36 53 6c 4b 24 49 72 } //G_U7fR_tN>Q3k0S_dat4P*WY<Js8+)C*!d?v!q!?O_6uVxc15t<>DV%r@7JUfyx2ycbCxK@ldX&C#K)?E<@Yu+6SlK$Ir  1
		$a_03_1 = {68 00 30 00 00 8b 45 b0 50 6a 00 6a ff ff 15 ?? ?? ?? ?? 89 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}