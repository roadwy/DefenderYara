
rule Trojan_Win32_Sarvdap_A{
	meta:
		description = "Trojan:Win32/Sarvdap.A,SIGNATURE_TYPE_PEHSTR_EXT,ffffff8c 00 ffffff8c 00 0c 00 00 64 00 "
		
	strings :
		$a_01_0 = {73 69 64 3d 25 73 3a 76 65 72 3d 25 73 3a 6c 6f 67 69 6e 3d 25 73 3a 70 61 73 73 3d 25 73 3a 70 6f 72 74 3d 25 75 } //0f 00  sid=%s:ver=%s:login=%s:pass=%s:port=%u
		$a_01_1 = {4d 53 5f 55 4e 41 54 5f 4d 4f 44 55 4c 45 5f 54 4f 5f 53 54 41 52 54 } //0a 00  MS_UNAT_MODULE_TO_START
		$a_01_2 = {73 61 76 65 2d 70 61 6e 64 61 73 2e 6e 65 74 } //0a 00  save-pandas.net
		$a_01_3 = {70 65 61 63 65 2d 77 69 74 68 2d 61 62 61 6d 61 2e 6f 72 67 } //0a 00  peace-with-abama.org
		$a_01_4 = {69 6c 6f 76 65 6d 69 63 72 6f 73 6f 66 74 76 65 72 79 6d 61 63 68 2e 63 6f 6d } //0a 00  ilovemicrosoftverymach.com
		$a_01_5 = {70 61 6c 6c 65 74 73 61 6c 62 75 6d 2e 6f 72 67 } //0a 00  palletsalbum.org
		$a_01_6 = {72 62 6c 2e 74 78 74 3f 73 69 67 6e 3d 25 73 26 6e 75 6d 62 61 3d 25 75 } //05 00  rbl.txt?sign=%s&numba=%u
		$a_01_7 = {62 6c 2e 73 70 61 6d 63 61 6e 6e 69 62 61 6c 2e 6f 72 67 0a 62 6c 2e 73 70 61 6d 63 6f 70 2e 6e 65 74 0a 70 62 6c 2e 73 70 61 6d 68 61 75 73 2e 6f 72 67 } //05 00 
		$a_01_8 = {73 72 76 5f 36 36 36 } //05 00  srv_666
		$a_01_9 = {37 34 68 68 64 73 66 62 77 65 79 75 59 47 48 75 69 65 62 77 65 64 77 65 64 77 49 4e 44 57 4e 42 44 57 } //05 00  74hhdsfbweyuYGHuiebwedwedwINDWNBDW
		$a_01_10 = {59 6a 64 6e 65 37 38 33 6e 62 47 47 77 74 37 33 68 } //05 00  Yjdne783nbGGwt73h
		$a_01_11 = {2e 6f 72 67 3a 32 33 38 39 2f 69 70 2e 70 68 70 } //00 00  .org:2389/ip.php
	condition:
		any of ($a_*)
 
}