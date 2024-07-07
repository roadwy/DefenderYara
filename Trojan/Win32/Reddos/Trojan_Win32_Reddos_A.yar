
rule Trojan_Win32_Reddos_A{
	meta:
		description = "Trojan:Win32/Reddos.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 20 2f 61 75 78 2f 63 6f 6e 2f 63 6f 6d 31 2f 2e 2e 2f 2e 2e 2f 5b 4c 41 47 5d 2e 2e 2f 2e 25 25 25 25 25 25 25 25 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 2e 2e 2f 66 61 6b 65 63 6e 6e 2f 72 65 64 66 6c 61 67 2d 73 74 61 79 2d 68 65 72 65 2e 70 68 70 2e 61 73 70 78 2e 61 73 70 2e 63 66 6d 2e 6a 73 70 20 48 54 54 50 2f 31 2e 31 } //2 GET /aux/con/com1/../../[LAG]../.%%%%%%%%./../../../../fakecnn/redflag-stay-here.php.aspx.asp.cfm.jsp HTTP/1.1
		$a_01_1 = {50 6f 77 65 72 65 64 20 62 79 20 5b 4c 41 47 5d } //1 Powered by [LAG]
		$a_01_2 = {52 65 64 46 6c 61 67 00 55 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}