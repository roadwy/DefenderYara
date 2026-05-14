
rule PWS_Win64_ArkanixStealer_CI_MTB{
	meta:
		description = "PWS:Win64/ArkanixStealer.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 72 6b 61 6e 69 78 53 74 65 61 6c 65 72 } //2 ArkanixStealer
		$a_01_1 = {42 72 6f 77 73 65 72 3a } //2 Browser:
		$a_01_2 = {63 6f 6f 6b 69 65 73 2e 74 78 74 } //2 cookies.txt
		$a_01_3 = {61 75 74 6f 66 69 6c 6c 73 2e 74 78 74 } //2 autofills.txt
		$a_01_4 = {63 72 65 64 69 74 5f 63 61 72 64 73 2e 74 78 74 } //2 credit_cards.txt
		$a_01_5 = {53 74 65 61 6d } //2 Steam
		$a_01_6 = {2f 61 70 69 2f 75 70 6c 6f 61 64 2f 64 69 72 65 63 74 } //2 /api/upload/direct
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}