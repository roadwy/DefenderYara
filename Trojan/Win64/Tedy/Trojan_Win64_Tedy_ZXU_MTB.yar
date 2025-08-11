
rule Trojan_Win64_Tedy_ZXU_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ZXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_81_0 = {21 20 66 75 64 20 63 61 74 20 73 68 69 74 20 61 6c 73 6f 20 66 75 63 6b 20 6e 69 67 67 65 72 73 20 66 72 66 72 66 72 2e } //6 ! fud cat shit also fuck niggers frfrfr.
		$a_81_1 = {30 58 59 5a 41 58 41 59 } //5 0XYZAXAY
	condition:
		((#a_81_0  & 1)*6+(#a_81_1  & 1)*5) >=11
 
}