
rule Trojan_Win32_Convagent_GJT_MTB{
	meta:
		description = "Trojan:Win32/Convagent.GJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e7 62 c6 45 db 68 c6 45 d4 38 c6 45 e9 67 c6 45 e3 52 c6 45 eb 34 c6 45 e8 48 c6 45 d9 64 c6 45 cf 49 c6 45 d7 67 c6 45 d2 38 c6 45 e5 41 c6 45 d0 34 c6 45 e2 55 c6 45 e4 4b c6 45 ea 31 c6 45 de 76 c6 45 d8 43 c6 45 d3 54 c6 45 ce 79 c6 45 d5 35 c6 45 dd 53 c6 45 cc 52 c6 45 dc 6c } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}