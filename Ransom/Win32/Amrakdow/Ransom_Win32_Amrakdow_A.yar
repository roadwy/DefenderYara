
rule Ransom_Win32_Amrakdow_A{
	meta:
		description = "Ransom:Win32/Amrakdow.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {40 6f 6e 69 6f 6e 6d 61 69 6c 2e 6f 72 67 } //1 @onionmail.org
		$a_01_1 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 68 61 73 20 62 65 65 6e 20 62 72 65 61 63 68 65 64 20 62 79 20 4b 61 72 6d 61 20 72 61 6e 73 6f 6d 77 61 72 65 20 67 72 6f 75 70 } //1 Your network has been breached by Karma ransomware group
		$a_01_2 = {61 00 61 00 61 00 5f 00 54 00 6f 00 75 00 63 00 68 00 4d 00 65 00 4e 00 6f 00 74 00 5f 00 2e 00 74 00 78 00 74 00 } //1 aaa_TouchMeNot_.txt
		$a_01_3 = {4b 00 41 00 52 00 4d 00 41 00 2d 00 41 00 47 00 52 00 45 00 45 00 2e 00 74 00 } //1 KARMA-AGREE.t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}