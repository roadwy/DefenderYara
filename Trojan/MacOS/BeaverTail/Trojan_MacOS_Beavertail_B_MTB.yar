
rule Trojan_MacOS_Beavertail_B_MTB{
	meta:
		description = "Trojan:MacOS/Beavertail.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {75 70 4c 44 42 46 69 6e 69 73 68 65 64 } //1 upLDBFinished
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 20 50 79 74 68 6f 6e 20 53 75 63 63 65 73 73 21 } //1 Download Python Success!
		$a_01_2 = {63 6c 69 65 6e 74 44 6f 77 6e 46 69 6e 69 73 68 65 64 } //1 clientDownFinished
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 20 43 6c 69 65 6e 74 20 53 75 63 63 65 73 73 21 } //1 Download Client Success!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}