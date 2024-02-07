
rule TrojanSpy_Win32_Banker_UUC{
	meta:
		description = "TrojanSpy:Win32/Banker.UUC,SIGNATURE_TYPE_PEHSTR,09 00 09 00 08 00 00 04 00 "
		
	strings :
		$a_01_0 = {2f 49 4e 56 4f 4b 45 3a 53 68 75 74 64 6f 77 6e 3a 4e 6f 50 72 6f 6d 70 74 } //01 00  /INVOKE:Shutdown:NoPrompt
		$a_01_1 = {61 78 61 62 61 6e 71 75 65 2e 66 72 2f 63 6c 69 65 6e 74 2f 73 61 75 74 68 65 6e 74 69 66 69 63 61 74 69 6f 6e } //01 00  axabanque.fr/client/sauthentification
		$a_01_2 = {62 61 6e 65 73 74 6f 2e 65 73 } //01 00  banesto.es
		$a_01_3 = {2e 62 61 6e 6b 69 6e 67 70 6f 72 74 61 6c 2e } //01 00  .bankingportal.
		$a_01_4 = {73 65 67 75 72 69 64 61 64 2e 6b 43 6f 6c 6c 66 69 72 6d 61 2e 63 6c 61 76 65 31 } //01 00  seguridad.kCollfirma.clave1
		$a_01_5 = {5b 69 65 20 72 65 73 65 74 20 63 6f 6d 70 6c 65 74 65 5d } //01 00  [ie reset complete]
		$a_01_6 = {73 61 62 61 64 65 6c 6c 61 74 6c 61 6e 74 69 63 6f 2e 63 6f 6d } //01 00  sabadellatlantico.com
		$a_01_7 = {62 61 6e 63 61 6f 6e 6c 69 6e 65 2e } //00 00  bancaonline.
	condition:
		any of ($a_*)
 
}