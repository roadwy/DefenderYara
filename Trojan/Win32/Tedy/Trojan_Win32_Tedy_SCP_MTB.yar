
rule Trojan_Win32_Tedy_SCP_MTB{
	meta:
		description = "Trojan:Win32/Tedy.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c0 48 c7 44 24 20 ?? ?? ?? ?? 45 33 c9 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 ?? ?? ?? ?? 48 8d 54 24 30 48 8d 4c 24 50 e8 ?? ?? ?? ?? 48 8d 4c 24 50 e8 ?? ?? ?? ?? 4c 8b c0 c7 44 24 28 ?? ?? ?? ?? 4c 8b cb 48 89 5c 24 20 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 } //2
		$a_01_1 = {65 00 78 00 6f 00 74 00 31 00 63 00 2e 00 76 00 65 00 72 00 63 00 65 00 6c 00 2e 00 61 00 70 00 70 00 2f 00 6b 00 78 00 7a 00 2d 00 66 00 72 00 65 00 65 00 2f 00 69 00 64 00 6b 00 2f 00 6d 00 73 00 65 00 64 00 67 00 65 00 2e 00 65 00 78 00 65 00 } //1 exot1c.vercel.app/kxz-free/idk/msedge.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}