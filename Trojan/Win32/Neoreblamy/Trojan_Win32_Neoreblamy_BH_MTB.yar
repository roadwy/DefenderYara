
rule Trojan_Win32_Neoreblamy_BH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 47 71 44 6e 62 4d 48 5a 75 7a 4b 53 62 6c 4c 79 74 4a 55 68 6c 65 78 61 4a 45 72 } //2 HooGqDnbMHZuzKSblLytJUhlexaJEr
		$a_01_1 = {6a 6f 52 63 4a 42 70 43 74 6d 58 59 62 49 4c 65 4f 6f 76 59 72 46 48 4d 73 71 4c 47 } //1 joRcJBpCtmXYbILeOovYrFHMsqLG
		$a_01_2 = {6e 42 50 52 58 50 70 4e 51 49 65 63 46 55 68 61 6f 69 4d 75 43 67 42 70 4c 48 6d 6d 7a 75 } //1 nBPRXPpNQIecFUhaoiMuCgBpLHmmzu
		$a_01_3 = {50 52 72 6b 45 4f 57 73 4c 78 59 4b 68 75 55 79 4c 76 67 72 48 52 6f 6e 57 51 77 58 4d 76 6c 73 61 78 } //1 PRrkEOWsLxYKhuUyLvgrHRonWQwXMvlsax
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}