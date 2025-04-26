
rule Trojan_Win64_Zusy_B_MTB{
	meta:
		description = "Trojan:Win64/Zusy.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 65 72 44 4c 4c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 53 54 45 41 4c 45 52 44 4c 4c 2e 70 64 62 } //StealerDLL\x64\Release\STEALERDLL.pdb  4
		$a_80_1 = {4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 73 } //Monero\wallets  2
		$a_80_2 = {4d 6f 7a 69 6c 6c 61 20 54 68 75 6e 64 65 72 62 69 72 64 } //Mozilla Thunderbird  2
		$a_80_3 = {39 33 37 35 43 46 46 30 34 31 33 31 31 31 64 33 42 38 38 41 30 30 31 30 34 42 32 41 36 36 37 36 } //9375CFF0413111d3B88A00104B2A6676  1
		$a_80_4 = {6e 65 74 73 68 20 77 6c 61 6e 20 73 68 6f 77 20 70 72 6f 66 69 6c 65 73 } //netsh wlan show profiles  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=10
 
}