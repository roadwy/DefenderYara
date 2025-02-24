
rule Ransom_Win32_Genasom_GNS_MTB{
	meta:
		description = "Ransom:Win32/Genasom.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {40 40 00 c4 b3 4d 00 00 00 00 00 2e 3f 41 56 3f 24 63 6c 6f 6e 65 5f 69 6d ?? 6c 40 55 62 61 64 5f } //10
		$a_80_1 = {50 6c 65 61 73 65 20 72 65 6d 6f 76 65 20 6f 72 20 64 69 73 61 62 6c 65 20 74 68 65 20 73 79 73 74 65 6d 20 64 65 62 75 67 67 65 72 20 62 65 66 6f 72 65 20 74 72 79 69 6e 67 20 74 6f 20 72 75 6e 20 74 68 69 73 20 70 72 6f 67 72 61 6d 20 61 67 61 69 6e } //Please remove or disable the system debugger before trying to run this program again  1
		$a_80_2 = {59 6f 75 72 20 70 75 72 63 68 61 73 65 20 69 73 20 6e 6f 74 20 63 6f 6d 70 6c 65 74 65 2e 20 50 6c 65 61 73 65 20 72 65 61 74 74 65 6d 70 74 20 70 61 79 6d 65 6e 74 } //Your purchase is not complete. Please reattempt payment  1
		$a_80_3 = {59 6f 75 72 20 73 79 73 74 65 6d 20 68 61 73 20 62 65 65 6e 20 63 6f 72 72 65 63 74 65 64 2e } //Your system has been corrected.  1
		$a_80_4 = {59 6f 75 72 20 6c 69 63 65 6e 73 65 20 68 61 73 20 62 65 65 6e 20 72 65 6d 6f 76 65 64 } //Your license has been removed  1
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=14
 
}