
rule Trojan_Win32_Farfli_BO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75 } //1
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 30 73 74 2e 65 78 65 } //1 C:\Program Files\Common Files\scvh0st.exe
		$a_01_2 = {5b 53 63 72 6f 6c 6c 20 4c 6f 63 6b 5d } //1 [Scroll Lock]
		$a_01_3 = {5b 50 72 69 6e 74 20 53 63 72 65 65 6e 5d } //1 [Print Screen]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}