
rule Worm_Win32_Thorpiex_A{
	meta:
		description = "Worm:Win32/Thorpiex.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {84 c9 74 0c 8a 4e 01 8a 5a 01 46 42 32 d9 74 f0 80 3a 00 74 0f } //5
		$a_03_1 = {6a 00 6a 0d 68 00 01 00 00 56 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 10 57 ff d5 6a 00 6a 00 6a 08 57 ff d5 6a 00 6a 00 6a 02 57 ff d5 } //5
		$a_01_2 = {2f 69 6d 73 70 61 6d 2e 68 74 6d } //1 /imspam.htm
		$a_03_3 = {53 65 6e 64 20 4d 65 73 73 61 67 65 20 74 6f 20 47 72 6f 75 70 [0-20] 41 54 4c 3a 30 30 38 39 30 41 39 30 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}