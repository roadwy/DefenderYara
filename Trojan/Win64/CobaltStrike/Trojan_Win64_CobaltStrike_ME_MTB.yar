
rule Trojan_Win64_CobaltStrike_ME_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {f0 00 23 00 0b 02 0e 1d 00 bc 08 00 00 90 01 01 66 90 00 } //02 00 
		$a_01_1 = {e3 68 ee be b8 2f bf b7 47 54 57 91 d1 a3 6c 7c 22 09 44 c7 3c cc 31 54 67 78 87 60 ab 43 39 7c 36 5f 22 ca 94 02 59 31 77 b1 b7 53 8c d6 f3 cd } //00 00 
	condition:
		any of ($a_*)
 
}