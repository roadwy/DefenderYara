
rule Trojan_Win32_Vidar_PE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 db 09 f3 89 da 8b 5d ?? 6a 08 8f 45 ?? d1 c0 8a fc 8a e6 d1 cb ff 4d fc 75 ?? 56 83 e6 00 31 de 83 e0 00 31 f0 5e aa 49 75 c5 } //1
		$a_03_1 = {46 89 75 e4 2b 75 ?? 33 75 ?? 83 e0 00 09 f0 8b 75 ?? 0f b6 1c 30 89 7d ?? 31 ff 33 7d f8 89 fa 8b 7d e4 d3 c2 23 d3 ac 0a c2 88 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}