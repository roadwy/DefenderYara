
rule Trojan_BAT_NanoBot_MBAV_MTB{
	meta:
		description = "Trojan:BAT/NanoBot.MBAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 00 56 00 71 00 51 00 3e 00 3c 00 3e 00 3c 00 4d 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 45 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 2f 00 2f 00 38 00 3e 00 3c 00 3e 00 3c 00 4c 00 67 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 3c 00 3e 00 } //1 TVqQ><><M><><><><E><><><><//8><><Lg><><><><>
		$a_01_1 = {30 00 51 00 32 00 68 00 68 00 62 00 6d 00 64 00 6c 00 5a 00 44 00 35 00 69 00 58 00 31 00 38 00 31 00 58 00 7a 00 3e 00 3c 00 3e 00 3c 00 50 00 48 00 4a 00 70 00 59 00 32 00 68 00 55 00 5a 00 58 00 68 00 } //1 0Q2hhbmdlZD5iX181Xz><><PHJpY2hUZXh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}