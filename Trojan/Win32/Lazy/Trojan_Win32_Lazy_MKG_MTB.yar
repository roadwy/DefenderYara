
rule Trojan_Win32_Lazy_MKG_MTB{
	meta:
		description = "Trojan:Win32/Lazy.MKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4d fc 83 c4 20 8b 55 08 33 04 0a 33 c3 8b 5d f4 89 04 0b 83 c1 04 89 4d fc 8d 41 04 83 f8 08 } //20
		$a_01_1 = {8a c2 c1 ea 08 32 04 0e 88 04 0b 41 83 f9 08 } //10
		$a_01_2 = {41 43 52 33 2e 30 2e 65 78 65 } //5 ACR3.0.exe
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}