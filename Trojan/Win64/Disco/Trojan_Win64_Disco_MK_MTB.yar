
rule Trojan_Win64_Disco_MK_MTB{
	meta:
		description = "Trojan:Win64/Disco.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 05 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 54 61 73 6b 20 73 74 61 72 74 65 64 2e 20 45 6c 65 76 61 74 65 64 20 70 61 79 6c 6f 61 64 20 73 68 6f 75 6c 64 20 72 75 6e 20 73 68 6f 72 74 6c 79 2e } //15 [+] Task started. Elevated payload should run shortly.
		$a_01_1 = {4b 75 69 6e 61 5f 52 75 73 74 5f 45 78 74 72 61 63 74 6f 72 5f 4d 75 74 65 78 5f 56 32 } //10 Kuina_Rust_Extractor_Mutex_V2
		$a_01_2 = {5b 2d 5d 20 72 75 6e 5f 75 61 63 5f 62 79 70 61 73 73 3a 20 66 61 69 6c 65 64 20 74 6f 20 63 6f 70 79 } //5 [-] run_uac_bypass: failed to copy
		$a_01_3 = {57 65 62 20 44 61 74 61 63 72 65 64 69 74 5f 63 61 72 64 73 2e 74 78 74 43 72 65 64 69 74 20 43 61 72 64 73 } //3 Web Datacredit_cards.txtCredit Cards
		$a_01_4 = {66 69 6c 65 20 41 6c 6c 5f 50 61 73 73 77 6f 72 64 73 2e 74 78 74 } //2 file All_Passwords.txt
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2) >=35
 
}