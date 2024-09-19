
rule Trojan_BAT_LummaStealer_GP_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 4f 79 6c 67 4d 4c 76 52 63 6e 61 54 54 50 73 6e 42 63 } //DOylgMLvRcnaTTPsnBc  1
		$a_80_1 = {4f 65 72 67 42 63 61 41 47 50 53 78 47 49 43 4d 44 46 4a 78 6e 6a } //OergBcaAGPSxGICMDFJxnj  1
		$a_80_2 = {72 77 5a 56 79 53 6b 4b 46 61 48 58 48 50 63 6a 4e 57 77 5a 72 66 51 6b 6d 6a } //rwZVySkKFaHXHPcjNWwZrfQkmj  1
		$a_80_3 = {4c 79 70 4c 4c 43 4c 54 77 72 5a 54 52 75 41 74 68 63 66 78 45 48 53 } //LypLLCLTwrZTRuAthcfxEHS  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}