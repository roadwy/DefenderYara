
rule Ransom_Win32_Haperlock_A{
	meta:
		description = "Ransom:Win32/Haperlock.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {69 64 65 6e 74 69 74 79 3b 71 3d 31 2e 30 2c 20 2a 3b 71 3d 30 } //1 identity;q=1.0, *;q=0
		$a_01_1 = {69 6e 65 74 4f 70 65 6e 3a 20 5b 68 74 74 70 3a 2f 2f 25 73 25 73 5d 20 5b 25 73 5d 20 5b 25 73 5d } //1 inetOpen: [http://%s%s] [%s] [%s]
		$a_01_2 = {73 63 73 3a 20 77 61 69 74 69 6e 67 20 74 68 72 65 61 64 20 64 69 65 73 20 28 31 29 } //1 scs: waiting thread dies (1)
		$a_01_3 = {77 61 74 63 68 65 72 20 64 69 65 73 21 } //1 watcher dies!
		$a_01_4 = {64 65 63 72 79 70 74 20 61 6e 64 20 73 75 69 63 69 64 65 20 28 31 29 2e 2e 2e } //1 decrypt and suicide (1)...
		$a_01_5 = {66 69 6c 65 20 27 25 73 27 20 69 73 20 65 6e 63 72 79 70 74 65 64 2c 20 66 61 69 6c 69 6e 67 21 } //1 file '%s' is encrypted, failing!
		$a_01_6 = {70 72 6f 63 65 73 73 69 6e 67 20 25 75 20 73 75 62 64 69 72 73 2e 2e 2e } //1 processing %u subdirs...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}