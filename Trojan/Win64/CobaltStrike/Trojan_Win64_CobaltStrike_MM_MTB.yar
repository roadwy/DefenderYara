
rule Trojan_Win64_CobaltStrike_MM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {f0 00 23 00 0b 02 0e 1d 00 c0 08 00 00 c0 97 } //02 00 
		$a_01_1 = {ff 74 24 30 9d 48 8d 64 24 58 e8 53 92 7d 02 96 64 87 bd 01 9e e0 19 d8 81 e7 2b 86 03 eb 3c ad e1 f3 38 4f 6a 37 04 d7 b8 59 f4 bd 22 3c 71 40 } //00 00 
	condition:
		any of ($a_*)
 
}