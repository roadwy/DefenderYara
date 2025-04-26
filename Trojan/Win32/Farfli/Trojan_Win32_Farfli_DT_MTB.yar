
rule Trojan_Win32_Farfli_DT_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DT!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 80 04 11 7a 03 ca 8b 4d fc 80 34 11 59 03 ca 42 3b d0 7c e9 } //1
		$a_01_1 = {8b 54 24 08 53 8a 1a 88 19 41 42 84 db 75 f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}