
rule Trojan_BAT_FsocietyRAT_AMTB{
	meta:
		description = "Trojan:BAT/FsocietyRAT!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {46 73 6f 63 69 65 74 79 52 41 54 5f 43 6c 69 65 6e 74 2e 46 73 6f 63 69 65 74 79 41 67 65 6e 74 2b 3c [0-1f] 3e } //2
		$a_80_1 = {44 69 65 67 6f 20 46 73 6f 63 69 65 74 79 20 52 41 54 2e 70 64 62 } //Diego Fsociety RAT.pdb  1
		$a_80_2 = {43 6f 6f 6b 69 65 20 73 74 65 61 6c 69 6e 67 20 72 65 71 75 69 72 65 73 20 61 64 64 69 74 69 6f 6e 61 6c 20 6c 69 62 72 61 72 69 65 73 } //Cookie stealing requires additional libraries  1
		$a_80_3 = {46 53 4f 43 49 45 54 59 20 57 41 53 20 48 45 52 45 } //FSOCIETY WAS HERE  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*2) >=5
 
}