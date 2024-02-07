
rule Trojan_Win32_Banker_K{
	meta:
		description = "Trojan:Win32/Banker.K,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_10_0 = {66 75 6e 63 74 69 6f 6e 20 46 69 6e 64 50 72 6f 78 79 46 6f 72 55 52 4c 28 75 72 6c 2c 20 68 6f 73 74 29 } //01 00  function FindProxyForURL(url, host)
		$a_10_1 = {66 6f 72 20 2f 66 20 22 74 6f 6b 65 6e 73 3d 2a 22 20 25 25 7a 20 69 6e 20 28 27 64 69 72 20 22 25 68 6f 6d 65 70 61 74 68 25 5c 2e 2e 22 20 2f 62 20 2f 73 } //01 00  for /f "tokens=*" %%z in ('dir "%homepath%\.." /b /s
		$a_10_2 = {64 6e 73 52 65 73 6f 6c 76 65 28 22 67 6f 6f 67 6c 65 2e 70 6f 72 74 61 6c 76 69 70 62 72 61 73 69 6c 2e 63 6f 6d 22 29 3b } //01 00  dnsResolve("google.portalvipbrasil.com");
		$a_10_3 = {72 65 67 2e 65 78 65 20 61 64 64 20 22 25 6b 65 79 25 22 20 2f 76 20 22 41 75 74 6f 43 6f 6e 66 69 67 55 72 6c 22 20 2f 64 20 22 66 69 6c 65 3a 2f 2f 25 5f 61 61 61 25 22 20 2f 66 } //01 00  reg.exe add "%key%" /v "AutoConfigUrl" /d "file://%_aaa%" /f
		$a_10_4 = {3d 20 22 77 77 77 22 3b } //01 00  = "www";
		$a_10_5 = {3d 20 22 63 6f 6d 2e 62 72 22 3b } //01 00  = "com.br";
		$a_10_6 = {3d 20 22 62 2e 62 72 22 3b } //01 00  = "b.br";
		$a_10_7 = {2b 22 2e 63 72 65 64 69 63 61 72 64 2e 22 2b } //01 00  +".credicard."+
		$a_10_8 = {2b 22 2e 73 61 6e 74 61 6e 64 65 72 62 61 6e 65 73 70 61 2e 22 2b } //01 00  +".santanderbanespa."+
		$a_10_9 = {2b 22 2e 73 65 72 61 73 61 65 78 70 65 72 69 61 6e 2e 22 2b } //01 00  +".serasaexperian."+
		$a_10_10 = {2b 22 2e 62 61 6e 63 6f 64 6f 62 72 61 73 69 6c 2e 22 2b } //01 00  +".bancodobrasil."+
		$a_10_11 = {69 66 20 28 28 68 6f 73 74 20 3d 3d 20 22 73 61 6e 74 61 6e 64 65 72 2e } //01 00  if ((host == "santander.
		$a_10_12 = {61 74 74 72 69 62 20 2b 48 20 22 25 61 70 70 64 61 74 61 25 22 5c 21 7a 21 } //01 00  attrib +H "%appdata%"\!z!
		$a_10_13 = {6b 65 79 3d 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 } //00 00  key=HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Internet Settings
	condition:
		any of ($a_*)
 
}