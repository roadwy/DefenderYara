
rule Backdoor_BAT_Crysen_S_MTB{
	meta:
		description = "Backdoor:BAT/Crysen.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 66 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 75 20 73 79 73 74 65 6d 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 74 6e } //1 /c schtasks /create /f /sc onlogon /ru system /rl highest /tn
		$a_81_1 = {5c 6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 65 72 61 77 74 66 6f 53 } //1 \nuR\noisreVtnerruC\swodniW\tfosorciM\erawtfoS
		$a_81_2 = {50 61 73 74 65 62 69 6e } //1 Pastebin
		$a_81_3 = {53 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 41 6e 74 69 76 69 72 75 73 50 72 6f 64 75 63 74 } //1 Select * from AntivirusProduct
		$a_81_4 = {6d 61 73 74 65 72 4b 65 79 20 63 61 6e 20 6e 6f 74 20 62 65 20 6e 75 6c 6c 20 6f 72 20 65 6d 70 74 79 2e } //1 masterKey can not be null or empty.
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}