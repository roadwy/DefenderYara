
rule Trojan_Win32_Valcailoz_A{
	meta:
		description = "Trojan:Win32/Valcailoz.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 00 7a 00 6f 00 6c 00 63 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 6f 00 77 00 2e 00 70 00 68 00 70 00 } //4 .zolcai.com/gow.php
		$a_01_1 = {63 00 6f 00 6d 00 65 00 6c 00 6f 00 6f 00 6b 00 2e 00 7a 00 6f 00 6c 00 63 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 } //1 comelook.zolcai.com
		$a_01_2 = {65 00 6e 00 74 00 2e 00 7a 00 6f 00 6c 00 63 00 61 00 69 00 2e 00 63 00 6f 00 6d 00 } //1 ent.zolcai.com
		$a_01_3 = {6b 00 61 00 6e 00 67 00 6f 00 2e 00 7a 00 6f 00 6c 00 63 00 61 00 69 00 2e 00 } //1 kango.zolcai.
		$a_01_4 = {63 00 61 00 69 00 2e 00 67 00 65 00 64 00 75 00 6f 00 2e 00 6f 00 72 00 67 00 } //1 cai.geduo.org
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}