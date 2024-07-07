
rule Trojan_Win32_Stealc_DW_MTB{
	meta:
		description = "Trojan:Win32/Stealc.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {8a 44 0c 28 34 90 01 01 88 84 0c f4 00 00 00 41 3b ce 7c 90 00 } //1
		$a_03_1 = {c0 f1 c0 db c7 44 24 90 01 01 c6 db d1 d3 c7 44 24 90 01 01 de e1 d7 d1 c7 90 01 01 24 44 c6 db dd dc 90 00 } //1
		$a_01_2 = {44 65 73 6b 74 6f 70 5c 73 74 65 61 6c 65 72 5f 6d 6f 72 70 68 5c 4e 68 33 5a 6f 47 53 5a 44 6a 67 48 31 48 74 5c 73 74 65 61 6c 65 72 } //1 Desktop\stealer_morph\Nh3ZoGSZDjgH1Ht\stealer
		$a_01_3 = {43 00 72 00 65 00 64 00 69 00 74 00 43 00 61 00 72 00 64 00 73 00 2f 00 25 00 6c 00 73 00 5f 00 25 00 6c 00 73 00 2e 00 74 00 78 00 74 00 } //1 CreditCards/%ls_%ls.txt
		$a_01_4 = {41 00 75 00 74 00 6f 00 66 00 69 00 6c 00 6c 00 73 00 2f 00 25 00 6c 00 73 00 5f 00 25 00 6c 00 73 00 2e 00 74 00 78 00 74 00 } //1 Autofills/%ls_%ls.txt
		$a_01_5 = {57 00 61 00 6c 00 6c 00 65 00 74 00 73 00 2f 00 25 00 6c 00 73 00 5f 00 25 00 6c 00 73 00 5f 00 25 00 6c 00 73 00 } //1 Wallets/%ls_%ls_%ls
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}