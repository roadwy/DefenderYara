
rule Trojan_Win32_Redline_CCFG_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 6b 77 75 75 79 69 6b 65 64 71 75 66 75 72 6b 62 6c 76 61 71 62 6e 78 61 6e 74 72 62 6c 67 6f 65 7a 74 73 6e 66 69 78 77 62 6a 61 6c 6d 73 72 66 63 66 76 63 6a 72 68 70 74 73 79 6a 61 66 6a 61 68 6d 78 64 } //1 fkwuuyikedqufurkblvaqbnxantrblgoeztsnfixwbjalmsrfcfvcjrhptsyjafjahmxd
		$a_01_1 = {77 6a 76 74 74 6d 62 61 63 76 65 6d 67 69 75 75 6c 61 64 75 63 6d 65 71 63 6e 6a 62 61 74 79 68 6f 6a 77 64 69 75 66 72 75 79 6a 70 67 6a 79 64 6a 61 6a 7a 70 68 71 64 } //1 wjvttmbacvemgiuuladucmeqcnjbatyhojwdiufruyjpgjydjajzphqd
		$a_01_2 = {68 6f 66 67 71 6c 7a 79 65 6a 67 68 75 75 6a 71 63 67 6b 65 76 6f 63 75 6d 76 66 6e 69 65 68 6c 71 6f 6a 79 6a 7a 6a 78 73 63 67 77 62 74 69 70 78 7a 6e 63 } //1 hofgqlzyejghuujqcgkevocumvfniehlqojyjzjxscgwbtipxznc
		$a_01_3 = {76 6c 77 77 66 64 7a 67 74 6a 6f 6a 71 77 61 77 63 73 72 6e 66 6d 69 6a 62 65 79 69 62 61 65 67 69 74 61 72 75 62 63 64 64 69 79 76 72 66 } //1 vlwwfdzgtjojqwawcsrnfmijbeyibaegitarubcddiyvrf
		$a_01_4 = {75 78 68 6d 71 68 6d 79 79 76 67 75 61 61 68 6e 67 77 71 77 70 75 6c 70 6a 69 62 65 63 68 76 76 6f 68 73 79 67 62 64 71 76 64 65 69 66 71 74 79 6f 6b 73 6e 79 7a 74 61 6d 74 6a 64 63 64 77 72 73 67 } //1 uxhmqhmyyvguaahngwqwpulpjibechvvohsygbdqvdeifqtyoksnyztamtjdcdwrsg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}