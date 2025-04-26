
rule Trojan_BAT_TempRotor_F_dha{
	meta:
		description = "Trojan:BAT/TempRotor.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,2c 01 2c 01 03 00 00 "
		
	strings :
		$a_01_0 = {6b 48 76 73 77 47 79 76 6a 37 41 31 35 45 59 62 51 51 71 62 69 73 63 67 42 59 34 55 6d 4c 77 52 65 68 30 46 73 2f 6e 66 4e 66 77 42 } //100 kHvswGyvj7A15EYbQQqbiscgBY4UmLwReh0Fs/nfNfwB
		$a_01_1 = {4b 2e 44 65 66 61 75 6c 74 53 74 6f 72 61 67 65 2e 6b 65 79 } //100 K.DefaultStorage.key
		$a_01_2 = {4b 2e 44 65 66 61 75 6c 74 53 74 6f 72 61 67 65 2e 62 69 6e } //100 K.DefaultStorage.bin
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100) >=300
 
}