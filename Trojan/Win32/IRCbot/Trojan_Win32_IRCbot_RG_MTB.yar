
rule Trojan_Win32_IRCbot_RG_MTB{
	meta:
		description = "Trojan:Win32/IRCbot.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {bb d7 1e 4f 00 89 d0 e8 90 01 04 81 c0 0f 59 e7 fc 31 1f 09 d0 81 c0 f1 d3 3d 22 47 89 d0 39 f7 75 dd 90 00 } //2
		$a_02_1 = {83 ec 04 c7 04 24 90 01 04 8b 0c 24 83 c4 04 81 c7 90 01 04 e8 90 01 04 4e 31 08 29 f6 29 f6 81 c7 90 01 04 40 81 c7 90 01 04 39 d8 75 90 00 } //2
		$a_02_2 = {29 ff 4f e8 90 01 04 81 c7 f8 6d a5 e0 31 06 21 f9 81 ef 01 00 00 00 81 c6 01 00 00 00 81 ef 01 00 00 00 09 f9 09 cf 39 d6 75 90 00 } //2
		$a_02_3 = {29 ce 41 e8 90 01 04 29 f6 81 ee b2 63 fe 6b 31 3b 81 c1 fd 76 3c 9e 43 68 56 69 63 d3 5e 09 f1 39 c3 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}