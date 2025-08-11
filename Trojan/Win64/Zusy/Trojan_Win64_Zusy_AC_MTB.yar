
rule Trojan_Win64_Zusy_AC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 48 45 31 c0 41 b9 02 00 00 00 48 c7 c1 01 00 00 80 48 8d 15 ad 37 00 00 48 8d 44 24 38 48 89 44 24 20 ff 15 bd 77 00 00 85 c0 75 61 48 8d 05 d0 37 00 00 41 b9 01 00 00 00 45 31 c0 48 8b 4c 24 38 48 8d 15 ab 37 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}