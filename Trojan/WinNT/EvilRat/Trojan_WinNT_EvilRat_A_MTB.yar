
rule Trojan_WinNT_EvilRat_A_MTB{
	meta:
		description = "Trojan:WinNT/EvilRat.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 65 76 69 6c 63 6f 64 65 7a 2f 65 76 69 6c 72 61 74 2f 63 6c 69 65 6e 74 2f 42 72 6f 77 73 65 72 53 74 65 61 6c 65 72 } //1 /evilcodez/evilrat/client/BrowserStealer
		$a_02_1 = {2f 52 6f 61 6d 69 6e 67 [0-22] 55 73 65 72 20 44 61 74 61 2f 44 65 66 61 75 6c 74 2f 4c 6f 67 69 6e 20 44 61 74 61 } //1
		$a_00_2 = {73 74 65 61 6c 41 6c 6c } //1 stealAll
	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}