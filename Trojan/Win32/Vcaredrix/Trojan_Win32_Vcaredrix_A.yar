
rule Trojan_Win32_Vcaredrix_A{
	meta:
		description = "Trojan:Win32/Vcaredrix.A,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 41 44 53 5f 61 73 00 74 5f 65 6e 72 75 6e 00 } //01 00  档捥䅫卄慟s彴湥畲n
		$a_01_1 = {73 6f 75 72 63 65 3d 25 73 26 76 61 6c 75 65 3d 25 73 } //01 00  source=%s&value=%s
		$a_01_2 = {25 73 61 3d 25 64 3b 62 3d 25 64 3b 63 3d 25 64 3b } //01 00  %sa=%d;b=%d;c=%d;
		$a_01_3 = {73 65 74 5f 69 70 61 64 64 72 65 73 73 } //01 00  set_ipaddress
		$a_01_4 = {61 75 74 6f 72 75 6e 73 65 74 } //01 00  autorunset
		$a_01_5 = {78 73 65 63 76 61 2e 6e 65 74 } //01 00  xsecva.net
		$a_01_6 = {78 73 65 61 63 63 2e 78 73 65 } //01 00  xseacc.xse
		$a_01_7 = {70 69 64 3d 25 73 26 63 69 64 3d 25 73 } //01 00  pid=%s&cid=%s
		$a_01_8 = {61 63 63 5f 65 6e 75 6d } //01 00  acc_enum
		$a_01_9 = {3c 45 4b 65 79 77 6f 72 64 3e } //00 00  <EKeyword>
	condition:
		any of ($a_*)
 
}