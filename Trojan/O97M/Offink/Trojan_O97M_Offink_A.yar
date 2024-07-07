
rule Trojan_O97M_Offink_A{
	meta:
		description = "Trojan:O97M/Offink.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 65 78 28 49 6e 76 6f 6b 65 2d 52 65 73 74 4d 65 74 68 6f 64 20 2d 55 72 69 20 27 68 74 74 70 73 3a 2f 2f 43 4f 4c 4c 45 43 54 4f 52 5f 55 52 4c 2f 61 70 69 2f 46 69 6c 65 27 } //1 iex(Invoke-RestMethod -Uri 'https://COLLECTOR_URL/api/File'
		$a_00_1 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 22 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e } //1 objShell.Run ("powershell.exe -WindowStyle Hidden
		$a_00_2 = {2d 4d 65 74 68 6f 64 20 47 65 74 20 2d 48 65 61 64 65 72 73 20 40 7b 27 47 75 69 64 27 3d 27 } //1 -Method Get -Headers @{'Guid'='
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}