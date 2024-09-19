
rule Trojan_BAT_Redline_FZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.FZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_81_0 = {59 62 79 6e 57 57 6e 74 77 5a 59 4e 74 46 57 50 69 6b 67 4e 4b 77 61 46 2e 64 6c 6c } //2 YbynWWntwZYNtFWPikgNKwaF.dll
		$a_81_1 = {71 56 48 4e 57 69 43 70 41 63 52 64 69 47 66 67 43 6f 76 79 57 4d 49 4b 75 6a 68 63 61 } //2 qVHNWiCpAcRdiGfgCovyWMIKujhca
		$a_81_2 = {72 46 57 42 51 56 69 6a 6f 45 6f 53 79 41 48 76 4f 4c 71 6b 6e 6c 42 4e 70 42 43 71 65 } //1 rFWBQVijoEoSyAHvOLqknlBNpBCqe
		$a_81_3 = {54 4c 6c 45 79 70 48 7a 45 44 78 63 53 76 46 74 41 75 63 65 65 4a 44 46 46 43 63 } //1 TLlEypHzEDxcSvFtAuceeJDFFCc
		$a_81_4 = {44 4d 57 74 48 7a 6c 4d 46 76 62 55 77 57 5a 47 76 48 5a 50 44 4b 66 45 4c 75 6f 6f } //1 DMWtHzlMFvbUwWZGvHZPDKfELuoo
		$a_81_5 = {4b 62 7a 67 50 4e 77 59 59 4b 58 68 7a 74 68 53 4f 73 59 77 76 44 52 58 45 41 78 5a } //1 KbzgPNwYYKXhzthSOsYwvDRXEAxZ
		$a_81_6 = {76 4b 63 68 47 79 67 55 47 57 61 79 77 54 4a 4b 42 4d 61 53 6e 41 57 6f 44 52 52 64 76 } //1 vKchGygUGWaywTJKBMaSnAWoDRRdv
		$a_81_7 = {51 62 77 6e 66 63 62 51 64 4a 72 56 45 71 6d 79 6f 6d 76 64 76 44 53 70 65 54 } //1 QbwnfcbQdJrVEqmyomvdvDSpeT
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=10
 
}