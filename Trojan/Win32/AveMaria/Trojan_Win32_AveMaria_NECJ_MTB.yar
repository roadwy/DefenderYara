
rule Trojan_Win32_AveMaria_NECJ_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NECJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_01_0 = {74 72 69 63 68 72 6f 6d 61 74 69 63 69 73 6d } //5 trichromaticism
		$a_01_1 = {4b 65 6c 69 6b 6f 2e 62 61 74 } //5 Keliko.bat
		$a_01_2 = {73 68 61 6d 70 6f 6f 2e 64 61 74 } //5 shampoo.dat
		$a_01_3 = {6e 6f 72 6d 61 6c 20 76 61 6c 75 65 2e 70 70 74 } //5 normal value.ppt
		$a_01_4 = {64 65 73 65 72 76 65 64 6c 79 2e 70 6e 67 } //5 deservedly.png
		$a_01_5 = {4d 61 6f 6e 61 6e 20 53 70 6f 6b 65 6e 2e 7a 69 70 } //5 Maonan Spoken.zip
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=30
 
}