
rule Trojan_Win32_Tedy_PGGH_MTB{
	meta:
		description = "Trojan:Win32/Tedy.PGGH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 73 3a 2f 2f 78 69 61 6d 6f 2e 64 61 73 69 71 75 65 69 72 6f 73 2e 69 6e 66 6f 2f 66 75 69 77 66 62 6a 6b 73 64 2f 73 74 65 74 64 73 76 6a } //https://xiamo.dasiqueiros.info/fuiwfbjksd/stetdsvj  2
		$a_80_1 = {7a 63 39 6b 34 4f 4d 69 68 6b 79 78 70 4a 49 47 52 38 43 6a 78 56 67 6f 42 76 76 39 50 42 } //zc9k4OMihkyxpJIGR8CjxVgoBvv9PB  1
		$a_80_2 = {4b 65 65 74 39 36 76 55 6b 4d 64 4a 54 68 61 63 } //Keet96vUkMdJThac  1
		$a_80_3 = {69 76 6e 70 46 72 49 43 51 43 45 4b 6b 6c 43 69 } //ivnpFrICQCEKklCi  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}