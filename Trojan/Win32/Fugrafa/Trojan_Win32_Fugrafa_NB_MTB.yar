
rule Trojan_Win32_Fugrafa_NB_MTB{
	meta:
		description = "Trojan:Win32/Fugrafa.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 8d 4d f8 e8 df 01 ff ff 8d 4d f8 e8 87 01 00 00 0f b6 d0 85 d2 75 17 c7 45 f0 00 00 00 00 8d 4d f8 e8 51 01 00 00 8b 45 f0 e9 97 00 } //2
		$a_01_1 = {57 00 72 00 72 00 79 00 53 00 75 00 62 00 6d 00 65 00 72 00 67 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 WrrySubmerged.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}