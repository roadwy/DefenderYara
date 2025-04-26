
rule Trojan_Win64_LummaC_CCJU_MTB{
	meta:
		description = "Trojan:Win64/LummaC.CCJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 6f 70 20 72 65 76 65 72 73 69 6e 67 20 74 68 65 20 62 69 6e 61 72 79 } //1 Stop reversing the binary
		$a_01_1 = {52 65 63 6f 6e 73 69 64 65 72 20 79 6f 75 72 20 6c 69 66 65 20 63 68 6f 69 63 65 73 } //1 Reconsider your life choices
		$a_01_2 = {41 6e 64 20 67 6f 20 74 6f 75 63 68 20 73 6f 6d 65 20 67 72 61 73 73 } //1 And go touch some grass
		$a_01_3 = {5c 25 53 65 78 42 6f 74 25 5c 6d 6f 64 75 6c 65 73 5c 73 74 75 62 6d 61 69 6e } //5 \%SexBot%\modules\stubmain
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5) >=8
 
}