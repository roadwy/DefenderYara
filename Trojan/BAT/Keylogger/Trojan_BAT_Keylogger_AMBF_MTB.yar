
rule Trojan_BAT_Keylogger_AMBF_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AMBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 7a 7d 03 4b 9b 5d d1 f5 8e 38 93 54 10 01 4b d3 95 35 49 4b 1f 01 bd f3 cb f8 d9 24 74 6f d8 92 13 c4 27 7b bb 9c ad 03 1a 51 a0 eb b0 } //1
		$a_01_1 = {c7 6c 76 b4 f1 16 aa a5 a7 ea 3d 49 aa c1 87 44 77 c0 90 57 7c e7 2d d1 91 4a 80 bc df 69 fe 84 ff 5c 4b e0 49 82 b5 fe ea cd 22 e2 0f a1 9d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}