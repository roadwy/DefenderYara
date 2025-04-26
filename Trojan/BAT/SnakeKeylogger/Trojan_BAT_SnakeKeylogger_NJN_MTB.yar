
rule Trojan_BAT_SnakeKeylogger_NJN_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6e 6f 69 73 72 65 56 20 79 6c 62 6d 65 73 73 41 } //1 noisreV ylbmessA
		$a_81_1 = {6e 6f 69 73 72 65 56 74 63 75 64 6f 72 50 } //1 noisreVtcudorP
		$a_81_2 = {67 65 74 5f 50 61 74 68 41 6e 64 51 75 65 72 79 } //1 get_PathAndQuery
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 75 73 65 72 3a 70 61 73 73 77 6f 72 64 40 77 77 77 2e 63 6f 6e 74 6f 73 6f 2e 63 6f 6d 3a 38 30 2f 48 6f 6d 65 2f 49 6e 64 65 78 2e 68 74 6d } //1 https://user:password@www.contoso.com:80/Home/Index.htm
		$a_81_4 = {44 6e 73 53 61 66 65 48 6f 73 74 3a } //1 DnsSafeHost:
		$a_81_5 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_6 = {24 64 34 64 33 36 66 35 35 2d 38 33 30 66 2d 34 31 34 62 2d 38 33 63 33 2d 64 37 61 32 38 64 35 62 36 35 65 38 } //1 $d4d36f55-830f-414b-83c3-d7a28d5b65e8
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}