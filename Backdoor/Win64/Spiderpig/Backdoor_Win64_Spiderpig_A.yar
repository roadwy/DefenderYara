
rule Backdoor_Win64_Spiderpig_A{
	meta:
		description = "Backdoor:Win64/Spiderpig.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 [0-10] 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 [0-30] 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 70 69 64 [0-10] 65 78 65 00 6f 70 65 6e } //10
		$a_00_1 = {5c 53 70 69 64 65 72 2d 52 61 74 5c 43 6c 69 65 6e 74 5c } //1 \Spider-Rat\Client\
		$a_00_2 = {48 61 72 64 77 61 72 65 5c 44 65 73 63 72 69 70 74 69 6f 6e 5c 53 79 73 74 65 6d 5c 43 65 6e 74 72 61 6c 50 72 6f 63 65 73 73 6f 72 5c 30 } //1 Hardware\Description\System\CentralProcessor\0
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=11
 
}