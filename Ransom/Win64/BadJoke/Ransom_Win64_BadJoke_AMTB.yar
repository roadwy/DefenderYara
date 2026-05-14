
rule Ransom_Win64_BadJoke_AMTB{
	meta:
		description = "Ransom:Win64/BadJoke!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {44 45 45 52 20 48 41 43 4b 45 52 } //DEER HACKER  1
		$a_80_1 = {59 6f 75 72 20 50 43 20 69 73 20 50 77 6e 65 64 20 44 45 45 52 } //Your PC is Pwned DEER  1
		$a_80_2 = {44 45 45 52 20 57 41 53 20 48 45 52 45 21 20 59 6f 75 72 20 73 79 73 74 65 6d 20 69 73 20 70 77 6e 65 64 21 } //DEER WAS HERE! Your system is pwned!  1
		$a_80_3 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e 20 50 61 79 20 31 20 42 54 43 20 74 6f 20 72 65 73 74 6f 72 65 20 61 63 63 65 73 73 } //Your files have been encrypted. Pay 1 BTC to restore access  1
		$a_80_4 = {44 65 65 72 20 69 73 20 65 61 74 69 6e 67 20 74 68 65 20 72 65 67 69 73 74 72 79 } //Deer is eating the registry  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}