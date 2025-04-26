
rule Trojan_Win64_BlipSlide_A_dha{
	meta:
		description = "Trojan:Win64/BlipSlide.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 49 63 65 44 72 69 76 65 40 40 } //10 .?AVIceDrive@@
		$a_01_1 = {2e 3f 41 56 3f 24 57 69 6e 48 74 74 70 57 72 61 70 70 65 72 40 56 49 63 65 44 72 69 76 65 40 40 40 40 } //10 .?AV?$WinHttpWrapper@VIceDrive@@@@
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}