
rule Trojan_Win32_Sefnit_AU{
	meta:
		description = "Trojan:Win32/Sefnit.AU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {bb 8c ac 00 00 66 33 1c 01 66 89 18 03 c7 4a } //2
		$a_01_1 = {e4 ac f8 ac f8 ac fc ac b6 ac a3 ac a3 ac ff ac fe ac fa ac f9 ac fc ac e8 ac a2 ac e2 ac e9 ac f8 ac } //1
		$a_01_2 = {bb ed a2 00 00 66 33 1c 01 66 89 18 83 c0 02 } //2
		$a_01_3 = {9e a2 88 a2 9f a2 9b a2 84 a2 8e a2 88 a2 c0 a2 9e a2 99 a2 8c a2 99 a2 c3 a2 8e a2 82 a2 80 a2 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Sefnit_AU_2{
	meta:
		description = "Trojan:Win32/Sefnit.AU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 72 00 75 00 20 00 22 00 53 00 59 00 53 00 54 00 45 00 4d 00 22 00 20 00 2f 00 73 00 63 00 20 00 68 00 6f 00 75 00 72 00 6c 00 79 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 72 00 20 00 22 00 25 00 73 00 20 00 2f 00 77 00 22 00 20 00 2f 00 73 00 74 00 20 00 30 00 30 00 3a 00 30 00 30 00 3a 00 30 00 30 00 } //1 /create /tn "%s" /ru "SYSTEM" /sc hourly /mo 1 /tr "%s /w" /st 00:00:00
		$a_03_1 = {7d 0a 68 57 00 07 80 e8 ?? ?? ff ff 89 79 f4 8b 0e 33 d2 66 89 51 18 b9 ?? ?? ?? ?? 2b c8 8b d7 bb ?? ?? 00 00 66 33 1c 01 66 89 18 83 c0 02 4a 75 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}