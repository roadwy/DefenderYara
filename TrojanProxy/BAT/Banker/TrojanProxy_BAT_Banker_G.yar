
rule TrojanProxy_BAT_Banker_G{
	meta:
		description = "TrojanProxy:BAT/Banker.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 64 62 22 20 28 73 74 61 72 74 20 2f 6c 6f 77 20 2f 6d 69 6e 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 22 68 74 74 70 3a 2f 2f } //00 00  .db" (start /low /min iexplore.exe "http://
	condition:
		any of ($a_*)
 
}
rule TrojanProxy_BAT_Banker_G_2{
	meta:
		description = "TrojanProxy:BAT/Banker.G,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 20 00 46 00 69 00 6e 00 64 00 50 00 72 00 6f 00 78 00 79 00 46 00 6f 00 72 00 55 00 52 00 4c 00 28 00 75 00 72 00 6c 00 2c 00 20 00 68 00 6f 00 73 00 74 00 29 00 } //02 00  function FindProxyForURL(url, host)
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 62 00 65 00 63 00 6f 00 6c 00 6c 00 65 00 67 00 65 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 } //02 00  http://www.becollege.info/
		$a_01_2 = {26 00 6e 00 65 00 74 00 43 00 61 00 72 00 64 00 3d 00 } //02 00  &netCard=
		$a_01_3 = {74 00 66 00 69 00 6c 00 65 00 2e 00 6a 00 73 00 70 00 } //01 00  tfile.jsp
		$a_01_4 = {42 00 61 00 6e 00 63 00 6f 00 20 00 64 00 6f 00 20 00 42 00 72 00 61 00 73 00 69 00 6c 00 } //01 00  Banco do Brasil
		$a_01_5 = {42 00 61 00 6e 00 65 00 73 00 65 00 } //01 00  Banese
		$a_01_6 = {2a 00 63 00 69 00 74 00 69 00 62 00 61 00 6e 00 6b 00 2a 00 } //00 00  *citibank*
	condition:
		any of ($a_*)
 
}