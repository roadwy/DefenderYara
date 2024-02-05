
rule Trojan_Win32_Kimsuk_B{
	meta:
		description = "Trojan:Win32/Kimsuk.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4c 10 ff 8a 1c 10 32 d9 88 1c 10 48 85 c0 7f ef 8a 02 5f 34 ac 5e 88 02 c6 04 2a 00 } //01 00 
		$a_01_1 = {0f be 04 1a 03 f0 8b fa 8b ce 33 c0 c1 e9 0e c1 e6 12 03 f1 83 c9 ff 43 f2 ae f7 d1 49 3b d9 72 df } //00 00 
	condition:
		any of ($a_*)
 
}