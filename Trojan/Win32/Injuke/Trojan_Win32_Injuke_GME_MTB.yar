
rule Trojan_Win32_Injuke_GME_MTB{
	meta:
		description = "Trojan:Win32/Injuke.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c6 45 d0 88 c6 45 d1 f9 c6 45 d2 d4 c6 45 d3 60 c6 45 d4 3a c6 45 d5 53 c6 45 d6 43 c6 45 d7 1a c6 45 d8 b5 c6 45 d9 6c c6 45 da e0 c6 45 db 47 c6 45 dc 47 8d 55 e0 89 15 } //0a 00 
		$a_01_1 = {6a 40 68 0d 80 01 00 8d 95 d0 7f fe ff 52 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}