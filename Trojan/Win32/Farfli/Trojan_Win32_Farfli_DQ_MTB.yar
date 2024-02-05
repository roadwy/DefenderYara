
rule Trojan_Win32_Farfli_DQ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {46 69 6c 65 20 64 61 6d 61 67 65 64 20 6f 72 20 69 6e 66 65 63 74 65 64 20 62 79 20 76 69 72 75 73 21 } //File damaged or infected by virus!  01 00 
		$a_80_1 = {44 65 62 75 67 67 65 72 20 64 65 74 65 63 74 65 64 20 20 2d 20 70 6c 65 61 73 65 20 63 6c 6f 73 65 20 69 74 20 64 6f 77 6e 20 61 6e 64 20 72 65 73 74 61 72 74 } //Debugger detected  - please close it down and restart  01 00 
		$a_80_2 = {73 65 72 76 69 63 65 20 69 6e 73 74 61 6c 6c 65 64 20 6d 65 61 6e 73 20 74 68 61 74 20 79 6f 75 20 61 72 65 20 72 75 6e 6e 69 6e 67 20 61 20 64 65 62 75 67 67 65 72 21 } //service installed means that you are running a debugger!  01 00 
		$a_80_3 = {59 6f 75 72 20 66 69 72 65 77 61 6c 6c 20 68 61 73 20 62 6c 6f 63 6b 65 64 20 61 63 63 65 73 73 20 74 6f 20 69 6e 74 65 72 6e 65 74 } //Your firewall has blocked access to internet  01 00 
		$a_80_4 = {68 74 74 70 3a 2f 2f 32 74 68 2e 79 79 73 73 73 2e 69 6e 66 6f 2f 67 65 6e 65 72 61 6c 2f 61 63 74 69 76 61 74 69 6f 6e 2f 63 6f 75 6e 74 31 2e 61 73 70 3f } //http://2th.yysss.info/general/activation/count1.asp?  01 00 
		$a_80_5 = {55 52 4c 53 65 6e 48 70 64 } //URLSenHpd  01 00 
		$a_80_6 = {50 6c 65 61 73 65 20 72 65 73 74 61 72 74 20 74 68 69 73 20 61 70 6c 69 63 61 74 69 6f 6e 20 73 6f 20 74 68 65 20 66 69 6c 65 20 63 61 6e 20 62 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 61 67 61 69 6e 21 } //Please restart this aplication so the file can be downloaded again!  00 00 
	condition:
		any of ($a_*)
 
}