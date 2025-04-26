
rule Trojan_Win32_KeyLogger_ASL_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 d2 fe c8 f7 d1 ff 44 24 00 23 d1 f6 f0 66 f7 d0 89 14 26 f7 6c 24 } //5
		$a_01_1 = {02 2b bc 53 20 c1 a9 24 66 80 75 66 7a 03 67 e2 cf 73 6b 58 9c c8 ce 9c a5 b2 d2 48 7c f3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}