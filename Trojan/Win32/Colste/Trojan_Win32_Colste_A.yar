
rule Trojan_Win32_Colste_A{
	meta:
		description = "Trojan:Win32/Colste.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2a 00 77 00 61 00 6c 00 6c 00 65 00 74 00 2a 00 } //1 *wallet*
		$a_01_1 = {5c 00 44 00 72 00 6f 00 70 00 62 00 6f 00 78 00 5c 00 41 00 70 00 70 00 73 00 5c 00 42 00 6c 00 6f 00 63 00 6b 00 63 00 68 00 61 00 69 00 6e 00 2e 00 69 00 6e 00 66 00 6f 00 5c 00 } //1 \Dropbox\Apps\Blockchain.info\
		$a_01_2 = {41 88 04 32 83 f9 05 72 f1 8b c6 42 8d 78 01 8d 9b 00 00 00 00 8a 08 40 84 c9 75 f9 2b c7 3b d0 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}