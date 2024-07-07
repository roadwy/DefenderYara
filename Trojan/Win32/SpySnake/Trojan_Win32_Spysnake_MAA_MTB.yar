
rule Trojan_Win32_Spysnake_MAA_MTB{
	meta:
		description = "Trojan:Win32/Spysnake.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 10 33 c9 5b 85 ff 74 23 b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 f0 91 40 00 30 14 31 41 3b cf 72 dd } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}