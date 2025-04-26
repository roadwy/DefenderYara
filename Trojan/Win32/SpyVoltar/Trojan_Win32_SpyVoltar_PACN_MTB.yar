
rule Trojan_Win32_SpyVoltar_PACN_MTB{
	meta:
		description = "Trojan:Win32/SpyVoltar.PACN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 d0 29 d0 b9 0a 00 00 00 31 db 31 d2 f7 f1 83 c2 30 88 14 1c 43 85 c0 75 f1 } //1
		$a_01_1 = {68 bd 01 00 00 68 bd 01 00 00 6a 22 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}