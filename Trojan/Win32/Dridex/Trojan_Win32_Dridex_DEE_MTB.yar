
rule Trojan_Win32_Dridex_DEE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d dc 8b 55 f0 8a 5d db 8b 75 e4 32 1e 29 d0 8b 55 c0 88 1c 0a 8b 4d dc 8b 75 d4 01 c1 } //1
		$a_01_1 = {01 f9 81 e1 ff 00 00 00 8b 7d e8 8b 5d d0 8a 1c 1f 8b 7d e0 32 1c 0f 8b 4d e4 8b 7d d0 88 1c 39 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}