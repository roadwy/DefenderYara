
rule Trojan_Win32_Kryptik_S_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a d9 8a f9 80 e3 ?? c0 e1 ?? 0a 4c 28 ?? 80 e7 ?? c0 e3 ?? 0a 1c 28 c0 e7 ?? 0a 7c 28 } //1
		$a_02_1 = {8b d3 d3 ea 8b 4c 24 ?? 03 54 24 ?? 8d 04 19 33 f0 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}