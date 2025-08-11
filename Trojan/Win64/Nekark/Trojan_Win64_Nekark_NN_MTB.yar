
rule Trojan_Win64_Nekark_NN_MTB{
	meta:
		description = "Trojan:Win64/Nekark.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0a 00 00 "
		
	strings :
		$a_01_0 = {69 6e 20 65 73 65 63 75 7a 69 6f 6e 65 20 63 6f 6d 65 20 61 6d 6d 69 6e 69 73 74 72 61 74 6f 72 65 2e 20 52 69 61 76 76 69 6f 20 63 6f 6e 20 70 72 69 76 69 6c 65 67 69 20 65 6c 65 76 61 74 69 2e 2e 2e } //2 in esecuzione come amministratore. Riavvio con privilegi elevati...
		$a_01_1 = {49 6e 73 65 72 69 73 63 69 20 69 6c 20 74 65 73 74 6f 20 64 61 20 61 6e 61 6c 69 7a 7a 61 72 65 } //1 Inserisci il testo da analizzare
		$a_01_2 = {72 61 6d 65 72 73 6f 6e 20 70 61 74 72 69 63 6b 20 73 6f 6c 75 74 69 6f 6e 20 66 61 62 72 69 63 20 6f 6d 65 62 72 61 6c 65 73 72 74 75 70 20 62 65 72 61 69 74 6f 64 } //1 ramerson patrick solution fabric omebralesrtup beraitod
		$a_01_3 = {4e 65 73 73 75 6e 20 69 6e 70 75 74 20 72 69 63 65 76 75 74 6f 2e 20 55 74 69 6c 69 7a 7a 6f 20 64 65 6c 20 74 65 73 74 6f 20 70 72 65 64 65 66 69 6e 69 74 6f } //1 Nessun input ricevuto. Utilizzo del testo predefinito
		$a_01_4 = {6f 70 72 65 74 6f 72 73 61 2e 70 64 62 } //1 opretorsa.pdb
		$a_01_5 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath
		$a_01_6 = {49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 } //1 Invoke-WebRequest -Uri
		$a_01_7 = {44 6f 77 6e 6c 6f 61 64 20 64 65 6c 20 66 69 6c 65 20 33 20 66 61 6c 6c 69 74 6f } //1 Download del file 3 fallito
		$a_01_8 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 } //1 powershell -Command
		$a_01_9 = {43 61 72 74 65 6c 6c 65 20 61 67 67 69 75 6e 74 65 20 61 6c 6c 65 20 65 73 63 6c 75 73 69 6f 6e 69 20 64 69 20 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 } //1 Cartelle aggiunte alle esclusioni di Windows Defender
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=11
 
}