
rule Trojan_Win32_Farfli_BJ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b cb 2b cf 8a 14 01 80 f2 62 88 10 40 4e 75 } //1
		$a_01_1 = {8a 14 01 80 f2 19 80 c2 46 88 14 01 41 3b ce 7c } //1
		$a_01_2 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 30 73 74 2e 65 78 65 } //1 Program Files\Common Files\scvh0st.exe
		$a_01_3 = {66 75 63 6b 79 6f 75 } //1 fuckyou
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}