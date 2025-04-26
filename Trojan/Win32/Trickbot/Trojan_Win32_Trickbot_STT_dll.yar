
rule Trojan_Win32_Trickbot_STT_dll{
	meta:
		description = "Trojan:Win32/Trickbot.STT!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 52 46 54 33 57 36 2b 63 6e 47 53 73 65 4c 69 79 39 34 4e 42 62 4b 64 44 4a 4f 6b 67 48 78 61 6c 30 45 5a 71 37 76 55 56 75 6a 4d 49 68 6d 38 35 59 32 7a 72 6f 41 74 31 58 66 77 43 70 50 51 } //5 /RFT3W6+cnGSseLiy94NBbKdDJOkgHxal0EZq7vUVujMIhm85Y2zroAt1XfwCpPQ
		$a_01_1 = {6a 5a 57 4a 67 45 38 46 6f 72 54 68 75 4d 74 43 6b 79 53 49 44 50 73 31 77 59 6e 62 52 61 76 35 2b 33 64 56 69 7a 39 4b 51 36 70 6d 65 34 71 37 4f 42 30 48 78 2f 6c 41 32 58 47 55 4c 63 66 4e } //5 jZWJgE8ForThuMtCkySIDPs1wYnbRav5+3dViz9KQ6pme4q7OB0Hx/lA2XGULcfN
		$a_01_2 = {62 41 37 6d 4a 36 70 74 67 32 } //1 bA7mJ6ptg2
		$a_01_3 = {50 6c 7a 71 59 38 63 41 52 30 6a 41 } //1 PlzqY8cAR0jA
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}