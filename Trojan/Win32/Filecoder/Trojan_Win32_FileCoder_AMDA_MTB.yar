
rule Trojan_Win32_FileCoder_AMDA_MTB{
	meta:
		description = "Trojan:Win32/FileCoder.AMDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 61 7a 61 20 61 6e 64 20 74 68 65 20 52 65 73 69 73 74 61 6e 63 65 20 61 72 65 20 76 69 63 74 6f 72 69 6f 75 73 2e 20 49 73 72 61 65 6c 20 64 65 66 65 61 74 65 64 } //1 Gaza and the Resistance are victorious. Israel defeated
		$a_03_1 = {8d 41 e0 3c 5a 77 [0-0a] 99 f7 7d [0-18] 5b [0-0a] b9 5b 00 00 00 [0-05] f7 f9 8d 4a 20 88 0c 37 46 [0-0a] 84 c9 75 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}