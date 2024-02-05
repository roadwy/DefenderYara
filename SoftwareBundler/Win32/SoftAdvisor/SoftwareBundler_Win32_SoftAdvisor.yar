
rule SoftwareBundler_Win32_SoftAdvisor{
	meta:
		description = "SoftwareBundler:Win32/SoftAdvisor,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 6f 66 74 61 64 76 69 73 6f 72 2e 6f 72 67 2f 70 6c 61 79 65 72 5f 6f 66 66 65 72 2e 70 68 70 00 } //01 00 
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 49 6e 73 74 61 6c 6c 51 75 61 72 6b 00 } //01 00 
		$a_01_2 = {5c 50 6c 61 79 65 72 2e 65 78 65 00 } //01 00 
		$a_01_3 = {5c 49 6e 73 74 61 6c 6c 5c 52 50 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}