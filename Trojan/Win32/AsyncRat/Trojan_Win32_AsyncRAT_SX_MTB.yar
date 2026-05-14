
rule Trojan_Win32_AsyncRAT_SX_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {59 5a 02 18 8b 4c 24 ?? 89 fa 80 c3 2a 0f b6 c3 } //20
		$a_03_1 = {89 de 31 c0 f3 a4 8d b2 ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 d7 f3 aa 89 f7 b9 ?? ?? ?? ?? 8d 74 24 ?? f3 a4 89 d7 } //10
		$a_03_2 = {0f 95 c3 89 d9 01 d9 00 db 8b 54 24 ?? 01 d5 39 ef 0f 42 ef 84 c0 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_03_2  & 1)*5) >=35
 
}