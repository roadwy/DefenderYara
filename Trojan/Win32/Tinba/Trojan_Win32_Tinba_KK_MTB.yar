
rule Trojan_Win32_Tinba_KK_MTB{
	meta:
		description = "Trojan:Win32/Tinba.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 55 88 0f af 55 e4 8a 45 a8 2a c2 88 45 a8 0f be 4d 88 8b 55 9c 8d 84 0a a3 02 00 00 8b 4d 90 2b c8 89 4d 90 8b 55 c0 0f af 55 94 8b 45 94 2b c2 89 45 94 eb b8 } //20
		$a_01_1 = {c7 45 c8 54 61 42 00 0f be 4d d0 69 c9 a1 fc ff ff 0f af 4d b8 89 4d 90 c7 45 d8 60 61 42 00 ba cd 39 f6 ff 2b 55 94 89 55 90 c7 45 a4 6c 61 42 00 8b 45 90 03 45 c0 8a 4d 88 02 c8 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}