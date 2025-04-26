
rule Trojan_AndroidOS_Denofow_A{
	meta:
		description = "Trojan:AndroidOS/Denofow.A,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 75 72 62 6f 62 69 74 2e 6e 65 74 2f 33 71 69 6a 72 61 34 31 62 79 65 64 2e 68 74 6d 6c } //1 http://turbobit.net/3qijra41byed.html
		$a_01_1 = {65 6e 64 6f 66 74 68 65 77 6f 72 6c 64 } //1 endoftheworld
		$a_01_2 = {30 35 32 31 32 30 31 31 } //1 05212011
		$a_01_3 = {43 61 6e 6e 6f 74 20 74 61 6c 6b 20 72 69 67 68 74 20 6e 6f 77 2c 20 74 68 65 20 77 6f 72 6c 64 20 69 73 20 61 62 6f 75 74 20 74 6f 20 65 6e 64 } //1 Cannot talk right now, the world is about to end
		$a_01_4 = {4a 65 62 75 73 20 69 73 20 77 61 79 20 6f 76 65 72 20 64 75 65 20 66 6f 72 20 61 20 63 6f 6d 65 20 62 61 63 6b } //1 Jebus is way over due for a come back
		$a_01_5 = {49 74 73 20 74 68 65 20 52 61 70 74 75 72 65 73 2c 70 72 61 69 73 65 20 4a 65 62 75 73 } //1 Its the Raptures,praise Jebus
		$a_01_6 = {5a 50 72 65 70 61 72 65 20 74 6f 20 6d 65 65 74 20 74 68 79 20 6d 61 6b 65 72 2c 20 6d 61 6b 65 20 73 75 72 65 20 74 6f 20 68 65 64 67 65 20 79 6f 75 72 20 62 65 74 20 6a 75 73 74 20 69 6e 20 63 61 73 65 20 74 68 65 20 4d 75 73 6c 69 6d 73 20 77 65 72 65 20 72 69 67 68 74 } //1 ZPrepare to meet thy maker, make sure to hedge your bet just in case the Muslims were right
		$a_01_7 = {4a 75 73 74 20 73 61 77 20 74 68 65 20 66 6f 75 72 20 68 6f 72 73 65 6d 65 6e 20 6f 66 20 74 68 65 20 61 70 6f 63 61 6c 79 70 73 65 20 61 6e 64 20 6d 61 6e 20 64 69 64 20 74 68 65 79 20 68 61 76 65 20 74 68 65 20 77 6f 72 73 74 20 63 61 73 65 20 6f 66 20 72 6f 61 64 20 72 61 67 65 } //1 Just saw the four horsemen of the apocalypse and man did they have the worst case of road rage
		$a_01_8 = {45 73 20 65 6c 20 66 69 6e 20 64 65 6c 20 6d 75 6e 64 6f } //1 Es el fin del mundo
		$a_01_9 = {49 20 61 6d 20 69 6e 66 65 63 74 65 64 20 61 6e 64 20 61 6c 69 76 65 20 76 65 72 20 31 2e 30 30 } //1 I am infected and alive ver 1.00
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}