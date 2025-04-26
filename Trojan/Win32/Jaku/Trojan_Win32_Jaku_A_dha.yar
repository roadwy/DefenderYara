
rule Trojan_Win32_Jaku_A_dha{
	meta:
		description = "Trojan:Win32/Jaku.A!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 5c 42 6f 74 5c 47 6c 6f 62 61 6c 2e 63 70 70 00 5b 25 73 3a 25 30 33 64 5d 20 53 65 74 20 46 61 6b 65 20 49 45 20 41 67 65 6e 74 20 54 61 67 } //1
		$a_01_1 = {69 6e 64 65 78 2e 70 68 70 7c 75 69 64 7c 76 7c 70 69 7c 69 66 7c } //1 index.php|uid|v|pi|if|
		$a_01_2 = {7c 57 69 6e 64 6f 77 73 55 70 64 61 74 65 7c 73 79 73 74 65 6d 69 6e 66 6f 3b 6e 65 74 20 75 73 65 3b 6e 65 74 20 75 73 65 72 3b } //1 |WindowsUpdate|systeminfo;net use;net user;
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}