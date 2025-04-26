
rule Trojan_Win32_Drixed_RPX_MTB{
	meta:
		description = "Trojan:Win32/Drixed.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 62 c6 45 e5 92 c6 45 e6 9c c6 45 e7 e7 c6 45 e8 fd c6 45 e9 13 c6 45 ea a9 c6 45 eb d0 c6 45 ec 1c c6 45 ed b1 } //1
		$a_01_1 = {f6 17 80 2f 7c 47 e2 f8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}