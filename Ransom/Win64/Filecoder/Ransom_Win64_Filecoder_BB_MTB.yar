
rule Ransom_Win64_Filecoder_BB_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6f 6e 74 5f 57 6f 72 72 79 2e 74 78 74 } //01 00  Dont_Worry.txt
		$a_81_1 = {70 61 79 63 72 79 70 74 40 67 6d 61 69 6c 5f 63 6f 6d } //01 00  paycrypt@gmail_com
		$a_81_2 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //01 00  -----BEGIN PUBLIC KEY-----
		$a_81_3 = {2e 77 6e 63 72 79 } //00 00  .wncry
	condition:
		any of ($a_*)
 
}