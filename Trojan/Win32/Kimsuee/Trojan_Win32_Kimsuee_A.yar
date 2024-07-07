
rule Trojan_Win32_Kimsuee_A{
	meta:
		description = "Trojan:Win32/Kimsuee.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 22 20 22 25 73 22 20 69 6e 73 74 61 6c 6c 73 76 63 } //1 rundll32.exe" "%s" installsvc
		$a_01_1 = {5f 4d 59 5f 42 41 42 59 5f } //1 _MY_BABY_
		$a_01_2 = {68 74 74 70 3a 2f 2f 79 75 73 65 75 6e 67 2e 65 6c 69 6d 62 69 7a 2e 63 6f 6d 2f 73 75 62 2f } //1 http://yuseung.elimbiz.com/sub/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}